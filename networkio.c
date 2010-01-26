#define _LARGEFILE64_SOURCE

#include <limits.h>
#include <sys/time.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>

#include <apr_general.h>
#include <apr_tables.h>
#include <apr_strings.h>

#include "libiptc/libiptc.h"                                                
#include "iptables.h"                                                       

#include "ganglia.h"

// TODO:apr_pool_destroy, overflow 

static int verv = 0;
static const char * prog = "networkio";

enum { MAXLEN = 256 };
enum { SLEEP_TIME = 60 };

struct iface {
    struct ipt_ip ip;
    u_int64_t bcnt; // bytes
};

struct rule {
    char * app;
    struct timeval interval;
    apr_array_header_t * ifaces;
};

struct filter {
    apr_array_header_t * rules;
    char * table;
    char * chain;
};

struct config {
    apr_array_header_t * filters;
    int sleeptime;
    apr_pool_t * p;
} conf = { NULL, SLEEP_TIME, NULL };

struct rule *
find_rule(apr_array_header_t * rules, const char * app) {
    int i;
    for (i=0; i < rules->nelts; ++i) {
        struct rule * ret = ((struct rule **)rules->elts)[i];
        if (strcmp(ret->app, app) == 0) return ret;
    }
    return NULL;
}

struct iface *
new_iface(apr_pool_t * p, const char * src, const char * smsk,
        const char * dst, const char * dmsk) {
    struct iface * iface;
    struct ipt_ip ip;
    int res;
    static const char * zero = "0.0.0.0";

    iface = (struct iface *)apr_palloc(p, sizeof(struct iface));
    if (!iface) return NULL;

    memset(&ip, 0, sizeof(struct ipt_ip));
    if (strcmp(src, zero) == 0) smsk = zero;
    if (strcmp(dst, zero) == 0) dmsk = zero;

    res = inet_aton(src, &ip.src);
    if (!res) { 
        fprintf(stderr, "Cannot parse network address: %s\n", src); 
        return NULL; 
    }
    res = inet_aton(smsk, &ip.smsk);
    if (!res) { 
        fprintf(stderr, "Cannot parse network mask: %s\n", smsk);
        return NULL;
    }
    res = inet_aton(dst, &ip.dst);
    if (!res) { 
        fprintf(stderr, "Cannot parse network address: %s\n", dst);
        return NULL;
    }
    res = inet_aton(dmsk, &ip.dmsk);
    if (!res) { 
        fprintf(stderr, "Cannot parse network mask: %s\n", dmsk); 
        return NULL; 
    }
    memcpy(&iface->ip, &ip, sizeof(struct ipt_ip));
    iface->bcnt = 0;
    return iface;
}

struct rule *
new_rule(apr_pool_t * p, const char * app) {
    struct rule * r;

    r = (struct rule *)apr_palloc(p, sizeof(struct rule));
    if (!r) return NULL;
    r->app = apr_pstrdup(p, app);
    r->ifaces = apr_array_make(p, 32, sizeof(struct iface *));
    gettimeofday(&r->interval, NULL);
    return r;
}

int
is_match(const struct ipt_ip * l, const struct ipt_ip * r) {
    if (   l->src.s_addr == r->src.s_addr
            && l->smsk.s_addr == r->smsk.s_addr
            && l->dst.s_addr == r->dst.s_addr
            && l->dmsk.s_addr == r->dmsk.s_addr
       ) return 1;
    return 0;
}

int 
is_table(const char * t) {
    static const char * tables [] = { "filter", "nat", "mangle" };
    int i, l;
    for (i=0, l=sizeof(tables)/sizeof(tables[0]); i<l; ++i) {
        if (strcmp(tables[i], t) == 0)
            return 1;
    }
    return 0;
}

struct filter * 
new_filter(apr_pool_t * p, const char * table, const char * chain) {
    struct filter * f;
    if (!is_table(table)) {
        fprintf(stderr, "Not table: %s\n", table);
        return NULL;
    }
    f = (struct filter*)apr_palloc(p, sizeof(struct filter));
    if (!f) return NULL;
    f->table = apr_pstrdup(p, table);
    f->chain = apr_pstrdup(p, chain);
    f->rules = apr_array_make(p, 32, sizeof(struct rule *));
    return f;
}

int 
gen_netmask(int n, char * t) {
    if (n < 0 || n > 32) return 0;
    if (!t) return 0;
    unsigned int i=1;
    int m = 32 - n;
    while (n > 0) {
        i <<= 1;
        i = i | 1;
        n--;
    }
    i <<= m;
    sprintf(t, "%d.%d.%d.%d", (i>>24)&0xff, (i>>16)&0xff, (i>>8)&0xff, i&0xff);
    return 1;
}

#define IP_PARTS_NATIVE(n)			\
    (unsigned int)((n)>>24)&0xFF,			\
(unsigned int)((n)>>16)&0xFF,			\
(unsigned int)((n)>>8)&0xFF,			\
(unsigned int)((n)&0xFF)

#define IP_PARTS(n) IP_PARTS_NATIVE(ntohl(n))

void
dump_ipt(const struct ipt_ip * ip) {
    printf("SRC IP: %u.%u.%u.%u/%u.%u.%u.%u\n",
            IP_PARTS(ip->src.s_addr),IP_PARTS(ip->smsk.s_addr));
    printf("DST IP: %u.%u.%u.%u/%u.%u.%u.%u\n",
            IP_PARTS(ip->dst.s_addr),IP_PARTS(ip->dmsk.s_addr));
    /*
       for (i = 0; i < IFNAMSIZ; i++)
       printf("%c", ip->iniface_mask[i] ? 'X' : '.');
       printf("to `%s'/", ip->outiface);
       for (i = 0; i < IFNAMSIZ; i++)
       printf("%c", ip->outiface_mask[i] ? 'X' : '.');
       printf("\nProtocol: %u\n", ip->proto);
       printf("Flags: %02X\n", ip->flags);
       printf("Invflags: %02X\n", ip->invflags);
       */
}

int
config(const char * fname, int sleep) {
    struct config * c = &conf;

    apr_pool_create(&c->p, NULL);
    if (!c->p) {
        fprintf(stderr, "Cannot create apr_pool.\n");
        return 0;
    }
    c->filters = apr_array_make(c->p, 10, sizeof(struct filter *));

    FILE * fp;
    char buf[MAXLEN];
    if (!fname) fname = "config.ini";
    fp = fopen(fname, "r");
    if (NULL == fp) {
        fprintf(stderr, "Cannot open file: %s\n", fname);
        return 0;
    }

    while ((fgets(buf, MAXLEN, fp)) != NULL) {
        struct filter * f;
        char * p = buf;
        int i,l;
        for (i=strlen(buf)-1; i>=0; --i) {
            if (buf[i] == '\n' || buf[i] == '\r' || buf[i] == '\t') {
                buf[i] = '\0';
            } else {
                break;
            }
        }
        for (i=0, l=strlen(buf); i<l; ++i)
            if (buf[i] == ' ' || buf[i] == '\t') p++;
            else break;
        if (strlen(p) == 0) continue;

        if (*p == ';') {
            continue;
        } else if (*p == '[') {
            char * end = strchr(p, ']');
            if (!end) {
                fprintf(stderr, "Not found `]': %s\n", buf);
                return 0;
            }
            * end = '\0';
            char table[MAXLEN], chain[MAXLEN];
            char * tag = strchr(p, ':');
            if (!tag) { 
                fprintf(stderr, "Not found user chain: %s\n", buf);
                return 0;
            } 
            * tag = '\0';
            strncpy(table, p+1, tag-p);
            strncpy(chain, tag+1, end-tag+1);
            if (!is_table(table))  {
                fprintf(stderr, "Not table: %s\n", table);
                continue;
            }
            f = new_filter(c->p, table, chain);
            *(struct filter**)apr_array_push(c->filters) = f;
        } else {
            char * t = strtok(p, " ");
            char app[MAXLEN], src[MAXLEN], smsk[MAXLEN], 
                 dst[MAXLEN], dmsk[MAXLEN];
            static const char * zero = "0.0.0.0";
            static const char * filled = "255.255.255.255";
            if (!t) {
                fprintf(stderr, "No application name: %s\n", buf);
                return 0;
            }
            strncpy(app, t, MAXLEN);

            strcpy(src, zero); strcpy(smsk,filled);
            strcpy(dst, zero); strcpy(dmsk,filled);
            t = strtok(NULL, " ");
            while (t != NULL) {
                char * t2 = strchr(t, '/');
                if (strncmp(t, "src:", 4) == 0) {
                    t += 4;
                    if (!t2) {
                        strcpy(src, t);
                    } else {
                        char net[16];
                        int n = atoi(t2+1);
                        * t2 = '\0';
                        strcpy(src, t);
                        gen_netmask(n, net);
                        strcpy(smsk, net);
                    }
                } else if (strncmp(t, "dst:", 4) == 0) {
                    t += 4;
                    if (!t2) {
                        strcpy(dst, t);
                    } else {
                        char net[16];
                        int n = atoi(t2+1);
                        * t2 = '\0';
                        strcpy(dst, t);
                        gen_netmask(n, net);
                        strcpy(dmsk, net);
                    }
                } else {
                    fprintf(stderr, "Unknown tags: src or dst: %s, token=%s\n", buf, t);
                    return 0;
                }
                t = strtok(NULL, " ");
            }
            struct rule * r = find_rule(f->rules, app);
            if (!r) {
                r = new_rule(c->p, app);
                if (!f || !r) {
                    fprintf(stderr, "No filter or No rule\n");
                    return 0;
                }
                *(struct rule**)apr_array_push(f->rules) = r;
            }
            struct iface * iface = new_iface(c->p, src, smsk, dst, dmsk);
            if (!r || !iface) {
                fprintf(stderr, "Cannot create rule: %s src %s:%s dst %s:%s\n",
                        app, src, smsk, dst, dmsk);
                return 0;
            }
            *(struct iface**)apr_array_push(r->ifaces) = iface;
        }
    }
    if (verv >= 1) {
        int i;
        apr_array_header_t * ary = c->filters;
        for (i=0; i<ary->nelts; ++i) {
            struct filter * f = ((struct filter**)ary->elts)[i];
            int j, k;
            printf("--- table:%s  chain:%s ----\n", f->table, f->chain);
            for (j=0; j<f->rules->nelts; ++j) {
                struct rule * r = ((struct rule**) f->rules->elts)[j];
                printf("*** %d:Registered: %s \n", j, r->app);
                for (k=0; k<r->ifaces->nelts; ++k) {
                    printf("****** iface:%d \n", k);
                    struct iface * iface = ((struct iface**) r->ifaces->elts)[k];
                    dump_ipt(&iface->ip);
                }
            }
        }
        puts("Configration done\n");
    }
    if (sleep) {
        conf.sleeptime = sleep;
    }

    fclose(fp);
    return 1;
}

u_int32_t  
get_bps(u_int64_t diff, struct rule * r) {
    struct timeval tv;
    double t = 0.0;
    if (diff > ULONG_MAX) {
        fprintf(stderr, "different overflow\n");
        return (u_int32_t)-1;
    }

    gettimeofday(&tv, NULL); // XXX: 2038 problem 
    t = (tv.tv_sec + 1.0e-6 * tv.tv_usec) - (r->interval.tv_sec + 1.0e-6 * r->interval.tv_usec);

    u_int32_t bps = (int)((diff * 8) / t);
    if (verv >= 1) {
        printf("%s: %3.3lf sec: receieved bytes %lu\n", r->app, t, (long unsigned int)diff);
        printf(" => %lu[bps]\n", (long unsigned)bps);
    }
    memcpy(&r->interval, &tv, sizeof(struct timeval));
    return bps;
}

/* from connstatd */
int                       sigflag;
Ganglia_pool              context;
Ganglia_metric            gmetric;
Ganglia_udp_send_channels channel;
Ganglia_gmond_config      gconfig;


static void SignalHandler(int sig)
{
    switch(sig){
        case SIGALRM:
            sigflag = 1;
            break;
    }
}

/* int gsend(int m) */
int gsend(char * app, int m)
{
    int  r;
    char v[8];
    sprintf(v,"%d",m);

    gmetric = Ganglia_metric_create(context);
    if(!gmetric){
        printf("Ganglia_metric_create error\n");
        return(1);
    }

    r=Ganglia_metric_set(gmetric, app, v, "uint32", "bps", 
            GANGLIA_SLOPE_BOTH, 60, 0);
    if (r != 0) {
        switch(r){
            case 1:
                fprintf(stderr,"gmetric parameters invalid. exiting.\n");
            case 2:
                fprintf(stderr,"one of your parameters has an invalid character '\"'. exiting.\n");
            case 3:
                fprintf(stderr,"the type parameter is not a valid type. exiting.\n");
            case 4:
                fprintf(stderr,"the value parameter does not represent a number. exiting.\n");
        }
        Ganglia_metric_destroy(gmetric);
        return(0);
    }

    r=Ganglia_metric_send(gmetric, channel);
    Ganglia_metric_destroy(gmetric);
    if(r){
        fprintf(stderr,"There was an error sending to %d of the send channels.\n", r);
        return(0);
    }
    return(1);
}

static 
void usage() {
    static const char * str = 
        "usage: %s [-d] [-f config] [-s sleep_time]\n"
        "          -d (debug mode ex. if [ -d -d -d ] are, more verbose than -d\n"
        "          -f config [default: config.ini]\n"
        "          -s sleep_time [default: %d]\n";
    fprintf(stderr, str, prog, SLEEP_TIME); 
    exit(0);
}

int do_handle() {
    struct config * c = &conf;
    int initialize = 0;

    while (1) {
        if (sigflag || !initialize) {
            int i, j;
            for (i=0; i<c->filters->nelts; ++i) {
                struct filter * f = ((struct filter **)c->filters->elts)[i];
                const char * table = f->table;
                const char * chain;
                iptc_handle_t handle;

                handle = iptc_init(table);
                if (!handle) {
                    fprintf(stderr, "Error initialize: %s\n", iptc_strerror(errno));
                    return errno;
                }
                for (chain = iptc_first_chain(&handle); 
                        chain; 
                        chain = iptc_next_chain(&handle)) {
                    if (strcmp(f->chain, chain) != 0) 
                        continue;

                    const struct ipt_entry * e = iptc_first_rule(chain, &handle);
                    for ( ; e; e = iptc_next_rule(e, &handle)) {
                        if (verv >= 4) dump_ipt(&e->ip);
                    }
                    for (j=0; j<f->rules->nelts; ++j) {
                        struct rule * r = ((struct rule **)f->rules->elts)[j];
                        int k;
                        if (verv >= 4) {
                            printf("----%s:our rule dump info----\n", r->app);
                            for (k=0; k<r->ifaces->nelts; ++k) {
                                struct iface * iface = ((struct iface**) r->ifaces->elts)[k];
                                printf("   following %s:%d\n", r->app, k);
                                dump_ipt(&iface->ip);
                            }
                            puts("------------------------------\n");
                        }
                        // XXX: rewrite, initialize and not 
                        if (!initialize) {
                            for (k=0; k<r->ifaces->nelts; ++k) {
                                struct iface * iface = ((struct iface**)r->ifaces->elts)[k];
                                const struct ipt_entry * e = iptc_first_rule(chain, &handle);
                                for ( ; e; e = iptc_next_rule(e, &handle)) {
                                    if (is_match(&e->ip, &iface->ip)) {
                                        if (verv >= 3) {
                                            printf("********  %s:%d initialize to %llu\n",
                                                    r->app, k, (u_int64_t)e->counters.bcnt);
                                        }
                                        iface->bcnt = e->counters.bcnt;
                                    }
                                }
                            } 
                        } else {
                            u_int64_t diffbytes = 0;
                            for (k=0; k<r->ifaces->nelts; ++k) {
                                struct iface * iface = ((struct iface**)r->ifaces->elts)[k];
                                const struct ipt_entry * e = iptc_first_rule(chain, &handle);
                                for ( ; e; e = iptc_next_rule(e, &handle)) {
                                    if (is_match(&e->ip, &iface->ip)) {
                                        if (e->counters.bcnt >= iface->bcnt) {
                                            diffbytes += e->counters.bcnt - iface->bcnt;
                                        } else {
#ifndef ULLONG_MAX
# define ULLONG_MAX	18446744073709551615ULL
#endif
                                            diffbytes += ULLONG_MAX- iface->bcnt + e->counters.bcnt;
                                        }
                                        iface->bcnt = e->counters.bcnt;
                                    }
                                }
                            }
                            u_int32_t bps = get_bps(diffbytes, r);
                            if (bps != (u_int32_t)(-1) ) {
                                int res = gsend(r->app, bps);
                                if (!res) return 1;
                            }
                        }
                    }
                }
                iptc_free(&handle);
            }
        }
        if (!initialize)  {
            initialize = 1;
        }
        sigflag = 0;
        sleep(1);
    }
    return 0; // not reach
}

int
main(int argc, char ** argv) {
    int sleep = 0, r;
    timer_t t;
    struct itimerspec it;
    struct sigaction  sa;
    char * cname = "config.ini";

    while (argc > 1) {
        if (       strcmp(argv[1], "-s") == 0 && argc > 2) {
            sleep = atoi(argv[2]);
            argc-=2; argv+=2;
        } else if (strcmp(argv[1], "-f") == 0 && argc > 2) {
            cname = argv[2];
            argc-=2; argv+=2;
        } else if (strcmp(argv[1], "-d") == 0) {
            verv += 1;
            argc-=1; argv+=1;
        } else if (strcmp(argv[1], "-h") == 0) {
            usage();
        } else {
            fprintf(stderr, "Unknown Option: %s\n", argv[1]);
            usage();
        }
    }

    // initialize 
    context = Ganglia_pool_create(NULL);
    if(!context){
        printf("Ganglia_pool_create error\n");
        return(1);
    }
    gconfig = Ganglia_gmond_config_create("/etc/ganglia/gmond.conf",0);
    if(!gconfig){
        printf("Ganglia_gmond_config_create\n");
        return(1);
    }
    channel = Ganglia_udp_send_channels_create(context, gconfig);
    if(!channel){
        printf("Ganglia_udp_send_channels_create error\n");
        return(1);
    }
    r = config(cname, sleep);
    if (!r) exit(2);

    /*----- signal -----*/
    sigflag = 0;
    sa.sa_flags = 0;
    sa.sa_handler = SignalHandler;
    sigemptyset(&sa.sa_mask);
    if(sigaction(SIGALRM, &sa, NULL) == -1){
        fprintf(stderr, "sigaction error\n");
        return(1);
    }
    /*----- timer -----*/
    it.it_interval.tv_sec  = conf.sleeptime;
    it.it_interval.tv_nsec = 0;
    it.it_value.tv_sec     = conf.sleeptime;
    it.it_value.tv_nsec    = 0;
    if(timer_create(CLOCK_REALTIME,NULL,&t) == -1){
        fprintf(stderr, "timer_create error\n");
        return(1);
    }
    if(timer_settime(t,0,&it,NULL) == -1){
        fprintf(stderr, "timer_settime error\n");
        return(1);
    }
    r = do_handle();
    timer_delete(t);
    return r;
}

/**
 * vim:tw=78:sw=4:ts=4: 
 ***/

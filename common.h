
#define AUDIT(x, args...) do { fprintf(stderr, "AUDIT: " x, ##args); } while (0)
#define DEBUGP(x, args...) do { fprintf(stdout, "DEBUGP: " x, ##args);} while (0)
#define WARNING(x, args...) do { fprintf(stderr, "WARNING: " x, ##args); } while (0)
#define PERROR(x) do { perror(x); _exit(1); } while (0)
#define ERROR(x, args...) do { fprintf(stderr,"ERROR: " x, ## args); _exit(1); } while (0)

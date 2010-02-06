#define MASTER_DAEMON	   "./trusted.py"
#define MASTER_ARGV_SIZE   128
#define MASTER_NUM_OF_ARGV   5

int (*real_handler)(void);
static int nsyscalls = 0;

void start_trusted_process(const char *socketdir, pid_t pid);

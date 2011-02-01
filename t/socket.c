#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/in.h>

#define SIZE_BUFFER 336

int main(void) 
{
  char buf[SIZE_BUFFER];
  struct sockaddr_in addr;
  int s, ret, i;

  s = socket(AF_INET, SOCK_STREAM, 0);

  if (s < 0)
    {
      perror("socket()");
      return EXIT_FAILURE;
    }

  addr.sin_family       = PF_INET;
  addr.sin_port         = htons(22);
  addr.sin_addr.s_addr  = inet_aton("localhost");

  ret = connect(s, (struct sockaddr *)&addr, sizeof addr);

  if (ret < 0)
    {
      perror("connect()");
      return EXIT_FAILURE;
    }
  
  while (fgets(buf, SIZE_BUFFER, stdin) != NULL) {
    ret = write(s, buf, strlen(buf));
    
    if (ret < 0)
      {
        perror("write()");
        return EXIT_FAILURE;
      }

    if (ret == 0)
      break;
  }
  
  close(s);
  
  return EXIT_SUCCESS;
}

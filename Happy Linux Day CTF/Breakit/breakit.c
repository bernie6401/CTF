#include"stdio.h"
#include"stdlib.h"

int main(){
  char buffer[8];
  int secret = 8;
  
  gets(buffer);

  if(secret != 8){
    puts("Something wrong.");
    system("/bin/sh");
  } else {
    puts(buffer);
  }

  return 0;
}

#include <stdio.h>
#include <string.h>
int main() {
	int pass = 0;
	char pw[5];
	char user[5];

	printf("Enter the username:\n");
	gets(user);

	if(strncmp(user, "NISRA",5)==0) {
    	if(strncmp(pw, "12345",5)==0){
    		printf("Hello NISRA\n");
    		if(pass!=0){  			
    			printf("You are root now.\n");	 			
    		}
    	}
    	else	printf("You did not enter password or password is wrong .\n");
	}
	else	printf("You are not user.\n");

	return 0;
}
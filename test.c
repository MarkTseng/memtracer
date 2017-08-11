#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/types.h>


void *inc_x(void *x_void_ptr)
{
	int i = *(int *)x_void_ptr;
	printf("[%d] pthread %d \n",getpid(),i);
    char *p1, *p2;
    p1 = malloc(1024);
    p2 = calloc(1,4096);
    printf("th p1:%p\n", p1);
    printf("th p2:%p\n", p2);
    printf("th Hello, RA:%#x \n", __builtin_return_address(0));
    free(p1);
    free(p2);
	return NULL;
}

int say_hello(int x, int y, int z)
{
    char *p1, *p2;
    p1 = malloc(1024);
    p2 = calloc(1,4096);
    p2 = realloc(p2,8192);
    printf("p1:%p\n", p1);
    printf("p2:%p\n", p2);
    printf("Hello, RA:%#x \n", __builtin_return_address(0));
    free(p1);
    free(p2);
	free(NULL);
    return 100;
}

int main(int argc, char **argv)
{
    char *p1,*p2,*p3,*p4;
    int x = 0x55;
    int y = 0x56;
    int z = 0x57;
    int i = 0;
	pthread_t inc_x_thread[100];

	while(i<5)
	{	
		if(pthread_create(&inc_x_thread[i], NULL, inc_x, &i)) {

			fprintf(stderr, "Error creating thread\n");
			return 1;
		}
        p1 = malloc(0xc);
        printf("[%s] p1:%p\n", __func__,p1);
        p2 = malloc(0xc);
        printf("[%s] p2:%p\n", __func__,p2);
        p3 = malloc(0xc);
        printf("[%s] p3:%p\n", __func__,p3);
        p4 = malloc(0xc);
        printf("[%s] p4:%p\n", __func__,p4);
        say_hello(0x255, 0x256, 0x257);
        //sleep(1);
        free(p1);
        free(p2);
        free(p3);
        free(p4);
        p1 = malloc(0xc);
        printf("[%s] p1:%p\n", __func__,p1);
		free(p1);
        p1 = malloc(0xc);
        printf("[%s] p1:%p\n", __func__,p1);
		free(p1);
        p1 = malloc(0xc);
        printf("[%s] p1:%p\n", __func__,p1);
		free(p1);
        i++;
    }

	for(i=0;i<5;i++)
	{
	/* wait for the second thread to finish */
	if(pthread_join(inc_x_thread[i], NULL)) {

		fprintf(stderr, "Error joining thread\n");
		return 2;

	}
	}


    return 0;
}

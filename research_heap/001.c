#include <stdio.h>
#include<stdlib.h>
#include<string.h>
#include <unistd.h>

char *Size = NULL;
char *name = NULL;

void setup(){
	setvbuf(stdin, NULL, _IONBF, 0);
	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);
}

void menu(){
	puts("1. Your name.");
	puts("2. Change name.");
	puts("3. Remove name.");
	puts("4. Read name.");
	puts("5. Exit.");
	printf("> ");
}

int check(char *name){
	if(name == 0){
		puts("You need create name!");
		return 0;
	}
	return 1;
}

int main(){
	setup();
	long size;
	int choice;

	while(1){
		menu();
		scanf("%u", &choice);
		switch(choice){
		case 1:
			printf("Size: ");
			scanf("%ld", &size);
			name = malloc(size);
			if(!name || size < 0){
				break;
			}
			printf("Name: ");
			read(0, name + 8, size - 8);
			printf("Name: %s\n", name + 8);
			*(void **)(name + size - 8) = (void *)name;
			break;
		case 2:
			if(!check(name)) break;
			printf("Change name: ");
			read(0, name + 8, size);
			break;
		case 3:
			if(!check(name)) break;
			free(name);
			name = 0;
			puts("Done!");
			break;
		case 4:
			if(!check(name)) break;
			printf("Name: %s\n", name + 8);
			break;
		case 5:
			exit(0);
		default:
			puts("Invalid choice.");
		}
	}
	return 0;
}
#include <stdio.h>
#include <string.h>

struct personal_data{
	char name[5];
	char surname[5];
};

int main(){
	struct personal_data data;
	memset(data.name,0,sizeof(data.name));
	memset(data.name,0,sizeof(data));
	memset(data.name,0,sizeof(data)+1);
	printf(data.name);
	return 0;
}


#include<stdio.h>
int max(int a, int b);
int main(){
    int a, b, c;
    printf("请输入最大的两个数字b和c\n");
    scanf("%d %d",&a,&b);
    printf("最大的数是:%d\n",max(a,b));
    return 0;
}
int max(int a, int b){
    if(a > b){
        return a;
    }else{
        return b;
    }
}
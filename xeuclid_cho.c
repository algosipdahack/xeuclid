#include <stdio.h> 
#include <openssl/bn.h>
void printBN(char *msg,BIGNUM* a){
    char *number_str = BN_bn2dec(a);
    printf("%s %s\n",msg,number_str);
    OPENSSL_free(number_str);
}
BIGNUM *XEuclid(BIGNUM *x, BIGNUM *y, const BIGNUM *a, const BIGNUM *b)
{       BIGNUM *a1 = BN_new();
        BIGNUM *b1 = BN_new();
        BIGNUM *q = BN_new();
        BIGNUM *r = BN_new();
        BIGNUM *s1 = BN_new();
        BIGNUM *s2 = BN_new();
        BIGNUM *t1 = BN_new();
        BIGNUM *t2 = BN_new();
        BIGNUM *z1 = BN_new();
        BIGNUM *z2 = BN_new();
        BN_CTX *ctx = BN_CTX_new();
        BN_copy(a1,a);
        BN_copy(b1 ,b);
        BN_dec2bn(&s1, "1");
        BN_dec2bn(&s2, "0");
        BN_dec2bn(&t1, "0");
        BN_dec2bn(&t2, "1");

        if(BN_cmp(a,b)<0){
            BN_copy(a1,b);
            BN_copy(b1,a);
        }
        while(1){
            int ret = BN_div(q,r,a1,b1,ctx);
            if(BN_is_zero(r))break;
            BN_copy(z1,s2);
            BN_copy(z2 ,t2);

            BN_mul(s2,s2,q,ctx);
            BN_mul(t2,t2,q,ctx);
            BN_sub(s1,s1,s2);
            BN_sub(t1,t1,t2);
            BN_copy(s2,s1);
            BN_copy(t2,t1);
            BN_copy(s1,z1);
            BN_copy(t1,z2);
            BN_copy(a1,b1);
            BN_copy(b1,r);
        }
        BN_copy(x,s2);
        BN_copy(y,t2);
	if(ctx!=NULL) BN_CTX_free(ctx);
        return b1;
}

int main (int argc, char *argv[])
{
        BIGNUM *a = BN_new();
        BIGNUM *b = BN_new();
        BIGNUM *x = BN_new();
        BIGNUM *y = BN_new();
        BIGNUM *gcd;
        if(argc != 3){
                printf("usage: xeuclid num1 num2");
                return -1;
        }
        BN_dec2bn(&a, argv[1]);
        BN_dec2bn(&b, argv[2]);
        gcd = XEuclid(x,y,a,b);
        printBN("(a,b) = ", gcd);
        printBN("a = ", a);
        printBN("b = ", b);
        printBN("x = ", x);
        printBN("y = ", y);
        printf("%s*(%s) + %s*(%s) = %s\n",BN_bn2dec(a),BN_bn2dec(x),BN_bn2dec(b),BN_bn2dec(y),BN_bn2dec(gcd));

        if(a != NULL) BN_free(a);
        if(b != NULL) BN_free(b);
        if(x != NULL) BN_free(x);
        if(y != NULL) BN_free(y);
        if(gcd != NULL) BN_free(gcd);

        return 0;
}

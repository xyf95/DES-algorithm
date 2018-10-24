#include <iostream>  
#include <fstream>  
#include <bitset>  
#include <string>  
#include <sstream>

using namespace std;  

bitset<64> plaintext;
bitset<64> ciphertext; 
bitset<64> key;           
bitset<48> subkey[16];  
  
int PC_1[] = {57, 49, 41, 33, 25, 17, 9,  
               1, 58, 50, 42, 34, 26, 18,  
              10,  2, 59, 51, 43, 35, 27,  
              19, 11,  3, 60, 52, 44, 36,  
              63, 55, 47, 39, 31, 23, 15,  
               7, 62, 54, 46, 38, 30, 22,  
              14,  6, 61, 53, 45, 37, 29,  
              21, 13,  5, 28, 20, 12,  4};   
  

int PC_2[] = {14, 17, 11, 24,  1,  5,  
               3, 28, 15,  6, 21, 10,  
              23, 19, 12,  4, 26,  8,  
              16,  7, 27, 20, 13,  2,  
              41, 52, 31, 37, 47, 55,  
              30, 40, 51, 45, 33, 48,  
              44, 49, 39, 56, 34, 53,  
              46, 42, 50, 36, 29, 32};  
  

int shiftBits[] = {1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1};  
 

int SP_BOX[8][4][16] = {  
    {    
        {0x00808200,0x00008000,0x00808002,0x00000002,0x00000200,0x00808202,0x00800202,0x00800000,0x00000202,0x00800200,0x00008200,0x00808000,0x00008002,0x00800002,0x00000000,0x00008202},    
        {0x00000000,0x00808202,0x00008202,0x00008000,0x00808200,0x00000200,0x00808002,0x00000002,0x00800200,0x00008200,0x00808000,0x00800202,0x00800002,0x00008002,0x00000202,0x00800000},    
        {0x00008000,0x00000002,0x00808200,0x00800000,0x00808002,0x00008200,0x00000200,0x00800202,0x00808202,0x00808000,0x00800002,0x00008202,0x00000202,0x00800200,0x00008002,0x00000000},   
        {0x00808202,0x00808000,0x00800000,0x00000200,0x00008000,0x00800002,0x00000002,0x00008202,0x00008002,0x00800202,0x00000202,0x00808200,0x00800200,0x00000000,0x00008200,0x00808002}   
    },  
    {    
        {0x40084010,0x00004000,0x00080000,0x40080010,0x40000010,0x40084000,0x40004000,0x00000010,0x00084000,0x40004010,0x40000000,0x00084010,0x00080010,0x00000000,0x00004010,0x40080000},    
        {0x40004000,0x00084010,0x00000010,0x40004010,0x40084010,0x40000000,0x00080000,0x40080010,0x00080010,0x00000000,0x00004000,0x40080000,0x40000010,0x00084000,0x40084000,0x00004010},   
        {0x00000000,0x40080010,0x40004010,0x40084000,0x40080000,0x00000010,0x00084010,0x00004000,0x00004010,0x00080000,0x00080010,0x40000010,0x00084000,0x40004000,0x40000000,0x40084010},    
        {0x00084010,0x00080000,0x40080000,0x00004000,0x40004000,0x40084010,0x00000010,0x40000000,0x40084000,0x40000010,0x40004010,0x00080010,0x00000000,0x00004010,0x40080010,0x00084000}    
    },   
    {    
        {0x00000104,0x00000000,0x04000100,0x00010104,0x00010004,0x04000004,0x04010104,0x04010000,0x04000000,0x04010100,0x00010100,0x04010004,0x04000104,0x00010000,0x00000004,0x00000100},    
        {0x04010100,0x04010004,0x00000000,0x04000100,0x04000004,0x00010000,0x00010004,0x00000104,0x00000004,0x00000100,0x04010000,0x00010104,0x00010100,0x04000104,0x04010104,0x04000000},    
        {0x04010100,0x00010004,0x00010000,0x04000100,0x00000100,0x04010104,0x04000004,0x00000000,0x04000104,0x04000000,0x00000004,0x00010100,0x04010000,0x00000104,0x00010104,0x04010004},    
        {0x04000000,0x00000104,0x04010100,0x00000000,0x00010004,0x04000100,0x00000100,0x04010004,0x00010000,0x04010104,0x00010104,0x04000004,0x04000104,0x04010000,0x00000004,0x00010100}    
    },   
    {    
        {0x80401000,0x80001040,0x00401040,0x80400000,0x00000000,0x00401000,0x80000040,0x00400040,0x80000000,0x00400000,0x00000040,0x80001000,0x80400040,0x00001040,0x00001000,0x80401040},    
        {0x80001040,0x00000040,0x80400040,0x80001000,0x00401000,0x80401040,0x00000000,0x80400000,0x00001000,0x80401000,0x00400000,0x00001040,0x80000000,0x00400040,0x00401040,0x80000040},    
        {0x00400040,0x00401000,0x80000040,0x00000000,0x00001040,0x80400040,0x80401000,0x80001040,0x80401040,0x80000000,0x80400000,0x00401040,0x80001000,0x00400000,0x00000040,0x00001000},    
        {0x80400000,0x80401040,0x00000000,0x00401000,0x00400040,0x80000000,0x80001040,0x00000040,0x80000040,0x00001000,0x80001000,0x80400040,0x00001040,0x80401000,0x00400000,0x00401040}    
    },  
    {    
        {0x00000080,0x01040000,0x00040000,0x20000000,0x20040080,0x01000080,0x21000080,0x00040080,0x01000000,0x20040000,0x20000080,0x21040080,0x21040000,0x00000000,0x01040080,0x21000000},    
        {0x01040080,0x21000080,0x00000080,0x01040000,0x00040000,0x20040080,0x21040000,0x20000000,0x20040000,0x00000000,0x21040080,0x01000080,0x20000080,0x21000000,0x01000000,0x00040080},    
        {0x00040000,0x00000080,0x20000000,0x21000080,0x01000080,0x21040000,0x20040080,0x01000000,0x21040080,0x21000000,0x01040000,0x20040000,0x00040080,0x20000080,0x00000000,0x01040080},    
        {0x21000080,0x01000000,0x01040000,0x20040080,0x20000000,0x01040080,0x00000080,0x21040000,0x00040080,0x21040080,0x00000000,0x21000000,0x01000080,0x00040000,0x20040000,0x20000080}    
    },  
    {    
        {0x10000008,0x00002000,0x10200000,0x10202008,0x10002000,0x00200000,0x00200008,0x10000000,0x00000000,0x10002008,0x00202000,0x00000008,0x10200008,0x00202008,0x00002008,0x10202000},    
        {0x10200000,0x10202008,0x00000008,0x00200000,0x00202008,0x10000008,0x10002000,0x00002008,0x00200008,0x00002000,0x10002008,0x10200008,0x00000000,0x10202000,0x00202000,0x10000000},    
        {0x10002000,0x10200008,0x10202008,0x00002008,0x00200000,0x10000000,0x10000008,0x00202000,0x00202008,0x00000000,0x00000008,0x10200000,0x00002000,0x10002008,0x10202000,0x00200008},    
        {0x00000008,0x00202000,0x00200000,0x10000008,0x10002000,0x00002008,0x10202008,0x10200000,0x10202000,0x10200008,0x00002000,0x00202008,0x00200008,0x00000000,0x10000000,0x10002008}    
    },   
    {    
        {0x00100000,0x02000401,0x00000400,0x00100401,0x02100401,0x00000000,0x00000001,0x02100001,0x02000400,0x00100001,0x02000001,0x02100400,0x02100000,0x00000401,0x00100400,0x02000000},    
        {0x02100001,0x00000000,0x02000401,0x02100400,0x00100000,0x02000001,0x02000000,0x00000401,0x00100401,0x02000400,0x02100000,0x00100001,0x00000400,0x02100401,0x00000001,0x00100400},    
        {0x02000000,0x00100000,0x02000401,0x02100001,0x00100001,0x02000400,0x02100400,0x00100401,0x00000401,0x02100401,0x00100400,0x00000001,0x00000000,0x02100000,0x02000001,0x00000400},    
        {0x00100400,0x02000401,0x02100001,0x00000001,0x02000000,0x00100000,0x00000401,0x02100400,0x02000001,0x02100000,0x00000000,0x02100401,0x00100401,0x00000400,0x02000400,0x00100001}    
    },   
    {    
        {0x08000820,0x00020000,0x08000000,0x00000020,0x00020020,0x08020820,0x08020800,0x00000800,0x08020000,0x08000800,0x00020800,0x08020020,0x00000820,0x00000000,0x08000020,0x00020820},    
        {0x00000800,0x08020820,0x08000820,0x08000000,0x08020000,0x00020800,0x00020820,0x00000020,0x08000020,0x00000820,0x00020020,0x08020800,0x00000000,0x08020020,0x08000800,0x00020000},    
        {0x00020820,0x08020800,0x00000020,0x00000800,0x08000800,0x08000020,0x08020020,0x00020000,0x00000000,0x00020020,0x08020000,0x08000820,0x08020820,0x00020800,0x00000820,0x08000000},    
        {0x00020000,0x00000800,0x08020020,0x00020820,0x00000020,0x08020000,0x08000000,0x08000820,0x08020820,0x08000020,0x08000800,0x00000000,0x00020800,0x00000820,0x00020020,0x08020800}   
    }   
};   
 
bitset<64> f(bitset<64> Right, bitset<48> key)         //f function of DES, I use 64 bitset for the encrypt function bit combination
{  
    bitset<48> Expansion;  

    Expansion[47]=Right[0];               //you need to set the Expansion[47] and expansion[0] at first
    Expansion[0]=Right[31];               //we found that E expansion can be replaced by this algorithm, it will decrease time
	int i=0;
    for (int x=0;x<8;x++)
    for(int y=0; y<6; y++,i++)
    {
    if(x==0 && y==0)                //handle overflow problem
        continue;	
	else if(x==7 && y==5)            //handle overflow problem
        continue;	
	else 
	 Expansion[47-i]=Right[32-4*x - y];    
    }

	      
    Expansion = Expansion ^ key;     //B= Expansion XOR Key

    bitset<64> output=0;  

    for(int i=0; i<48; i=i+6)    //B will be divide into 8 6-bit string, each string, B1B6 combine to row and B2B3B4B5 combine to column and find its corresponding result in S-box
    {  
        int row = Expansion[47-i]*2 + Expansion[47-i-5];       //row=B1*2+B6, same theory like expansion, and B1B6, B2B3B4B5 is in binary format, So row and col calculate them in dicimal format.
        int col = Expansion[47-i-1]*8 + Expansion[47-i-2]*4 + Expansion[47-i-3]*2 + Expansion[47-i-4];  //col=B2*8+B3*4+B4*2+B5

        int num = SP_BOX[i/6][row][col];             //SP box mix S-box and P box into one single box to decrease the time consume.
        bitset<64> binary(num);  
      
        output=output | binary;             //we don't need to permutation again, just conbine all SP-box result into output, that is the final result.
 
    } 
    return output;  
}  
   
bitset<56> leftShift(bitset<56> left, bitset<56> right, int shift)  //shift is a array to show how many bit we should shift left in this round. 
{   bitset<56> a=0xFFFFFFF;        //because I use 56 bitset to store left and right, not 28. So during left shift, there will bit be shifted into 29,30 position, I use a to delete them
    bitset<56> tmp1 = left;  
    bitset<56> tmp2 = right;
	bitset<56> subkey; 

	int i=28-shift;
	left=(tmp1<<shift| tmp1>>i) & a;       //first x bit will add to last position, than shift other bit left x postion. use a to delete overshift 
	right=(tmp2<<shift| tmp2>>i) & a; 
     
    subkey=left<<28 | right;      //only two 56 bitset can be combine into one 56 bitset, that is the reason I use 56 bit in left and right
     return subkey;  
}   
 
void generateKeys()   //generate 16 56-bit subkeys 
{  
    bitset<56> PC01;  
    bitset<56> left;        //the reason I use 56 instead of 28 will be shown in function: leftShift
    bitset<56> right;  
    bitset<48> PC02;  

    for (int i=0; i<56; ++i)         //using table PC-1 to generate a 56-bit key
        PC01[55-i] = key[64 - PC_1[i]];  //the same as f function's expansion
                               

    for(int round=0; round<16; ++round)   //16 round need different subkey
    {  
        
        for(int i=28; i<56; ++i)     //Divide PC-1 result into left C and right D two 28 length key 
            left[i-28] = PC01[i];  //when we don't need to get the postion i of a string, but just copy a bitset to another, left[0-27]=PC01[28-55]

        for(int i=0; i<28; ++i)  
            right[i] = PC01[i];      //right[0-27]=PC01[0-27]

        PC01 = leftShift(left, right , shiftBits[round]);  //LEFT circular shift, get the new left and right and comebine them together

        for(int i=0; i<48; ++i)  
            PC02[47-i] = PC01[56 - PC_2[i]];        //just like the algorithm we generate PC-1 result, use another table, PC-2 generate the final subkey of each round.
        subkey[round] = PC02;  
    }  
}  

  bitset<64> StringtoBinary(string s)  
{   unsigned long long PC10;
    bitset<64> bits;  
    stringstream ss;
    ss.str(s);          //the content of string is the hex format of key/plaintext
    ss>>hex>>PC10;       //change hex format to decimal format
	bits = bitset<64>(PC10);    //change decimal format to binary format
    return bits;  
}  
  
bitset<64> encrypt(bitset<64>& plaintext)  
{  
    bitset<64> ciphertext;  
    bitset<64> IP_result;  
    bitset<64> left;  
    bitset<64> right;  
    bitset<64> newLeft;  
    int x=0;
    for(int i=0; i<8; i++,x+=8)  
     {
    IP_result[63-i] = plaintext[6+x];
    IP_result[55-i] = plaintext[4+x];
    IP_result[47-i] = plaintext[2+x];             //IP table can be replaced by this for loop
    IP_result[39-i] = plaintext[0+x];
    IP_result[31-i] = plaintext[7+x];
    IP_result[23-i] = plaintext[5+x];
    IP_result[15-i] = plaintext[3+x];
    IP_result[7-i]  = plaintext[1+x];
		} 

    for(int i=32; i<64; ++i)  
        left[i-32] = IP_result[i];        //divide IP result into two 32 bit sub-plaintext (L and R)
    for(int i=0; i<32; ++i)  
        right[i] = IP_result[i];  

    for(int round=0; round<16; ++round)  
    {  
        newLeft = right;                       //in each round, the input of left is the last round right result; 
        right = left ^ f(right,subkey[round]);   //the output of right is the last round left XOR f(last round right, subkey of this round);
        left = newLeft;                        //the output of left is the last round right;
    }  

    ciphertext=right<<32 | left;    //combine left and right, but this time right first than left!!!  R and L 


    IP_result = ciphertext;  
    int a=0;
    for(int i=0; i<8; i++,a++)  
    {
    ciphertext[63-8*i] = IP_result[24+i];   
    ciphertext[62-8*i] = IP_result[56+i];   
    ciphertext[61-8*i] = IP_result[16+i];            //IP-1 table can be replaced by this for loop
    ciphertext[60-8*i] = IP_result[48+i];  
    ciphertext[59-8*i] = IP_result[8+i];  
    ciphertext[58-8*i] = IP_result[40+i];  
    ciphertext[57-8*i] = IP_result[0+i];  
    ciphertext[56-8*i] = IP_result[32+i];  
	} 
    return ciphertext;  
}  
  

int main() {  
    string k1 = "8E71CF39";
    string k2 = "E73C9EF0";  
    string s1 = "37FEC937";  
    string s2 = "EC817E0F";  
    
    plaintext=StringtoBinary(s1)<<32 | StringtoBinary(s2);   //plaintext is the binary format of s1s2   "37FEC937EC817E0F"
    key=StringtoBinary(k1)<<32 | StringtoBinary(k2);        //plaintext is the binary format of k1k2   "8E71CF39E73C9EF0"

    generateKeys();   
	  
    ciphertext = encrypt(plaintext);  
    cout<<ciphertext<<endl;
    return 0;  
}  

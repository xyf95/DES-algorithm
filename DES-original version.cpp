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

int IP[] = {58, 50, 42, 34, 26, 18, 10, 2,
 60, 52, 44, 36, 28, 20, 12, 4,
 62, 54, 46, 38, 30, 22, 14, 6,
 64, 56, 48, 40, 32, 24, 16, 8,
 57, 49, 41, 33, 25, 17, 9, 1,
 59, 51, 43, 35, 27, 19, 11, 3,
 61, 53, 45, 37, 29, 21, 13, 5,
 63, 55, 47, 39, 31, 23, 15, 7};
 
int IP_1[] = {40, 8, 48, 16, 56, 24, 64, 32,
 39, 7, 47, 15, 55, 23, 63, 31,
 38, 6, 46, 14, 54, 22, 62, 30,
 37, 5, 45, 13, 53, 21, 61, 29,
 36, 4, 44, 12, 52, 20, 60, 28,
 35, 3, 43, 11, 51, 19, 59, 27,
 34, 2, 42, 10, 50, 18, 58, 26,
 33, 1, 41, 9, 49, 17, 57, 25};

int PC_1[] = {57, 49, 41, 33, 25, 17, 9,
 1, 58, 50, 42, 34, 26, 18,
 10, 2, 59, 51, 43, 35, 27,
 19, 11, 3, 60, 52, 44, 36,
 63, 55, 47, 39, 31, 23, 15,
 7, 62, 54, 46, 38, 30, 22,
 14, 6, 61, 53, 45, 37, 29,
 21, 13, 5, 28, 20, 12, 4};

int PC_2[] = {14, 17, 11, 24, 1, 5,
 3, 28, 15, 6, 21, 10,
 23, 19, 12, 4, 26, 8, 
 16, 7, 27, 20, 13, 2,
 41, 52, 31, 37, 47, 55,
 30, 40, 51, 45, 33, 48,
 44, 49, 39, 56, 34, 53,
 46, 42, 50, 36, 29, 32};

int shiftBits[] = {1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1};


int E[] = {32, 1, 2, 3, 4, 5,
 4, 5, 6, 7, 8, 9,
 8, 9, 10, 11, 12, 13,
 12, 13, 14, 15, 16, 17,
 16, 17, 18, 19, 20, 21,
 20, 21, 22, 23, 24, 25,
 24, 25, 26, 27, 28, 29,
 28, 29, 30, 31, 32, 1};

int S_BOX[8][4][16] = {
 {
 {14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7},
 {0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8},
 {4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0},
 {15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13}
 },
 {
 {15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10},
 {3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5},
 {0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15},
 {13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9}
 },
 {
 {10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8},
 {13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1},
 {13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7},
 {1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12}
 },
 {
 {7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15},
 {13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9}, 
 {10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4},
 {3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14}
 },
 {
 {2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9},
 {14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6},
 {4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14},
 {11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3}
 },
 {
 {12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11},
 {10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8},
 {9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6},
 {4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13}
 },
 {
 {4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1},
 {13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6},
 {1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2},
 {6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12}
 },
 {
 {13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7},
 {1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2},
 {7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8},
 {2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11}
 }
};

int P[] = {16, 7, 20, 21,
 29, 12, 28, 17,
 1, 15, 23, 26,
 5, 18, 31, 10,
 2, 8, 24, 14,
 32, 27, 3, 9,
 19, 13, 30, 6,
 22, 11, 4, 25 };

bitset<64> f(bitset<64> Right, bitset<48> key) //f function of DES, I use 64 bitset for the encrypt function bit combination
{
 bitset<48> Expansion; 
 for(int i=0; i<48; ++i)    //The output of bitset is the reverse of bitset[0],bitset[1]...,bitset[47]!!!, so both key and PC01 is this. That explain the for algorithm
 Expansion[47-i] = Right[32-E[i]]; //so string Expansion position 1 = Expansion[47] =string Right position 32 = key[0]

 Expansion = Expansion ^ key;           //B= Expansion XOR Key
 bitset<64> output;
 int x = 0;
 for(int i=0; i<48; i=i+6) //B will be divide into 8 6-bit string, each string, B1B6 combine to row and B2B3B4B5 combine to column and find its corresponding result in S-box
 {
 int row = Expansion[47-i]*2 + Expansion[47-i-5]; //row=B1*2+B6, same theory like expansion, and B1B6, B2B3B4B5 is in binary format, So row and col calculate them in dicimal format.
 int col = Expansion[47-i-1]*8 + Expansion[47-i-2]*4 + Expansion[47-i-3]*2 + Expansion[47-i-4];        //col=B2*8+B3*4+B4*2+B5
 int num = S_BOX[i/6][row][col];
 bitset<64> binary(num);
 binary=binary<< 4*(7-(i/6));       //use << and | to combine all 8 4-bit result into a 32 bit output
 output=output | binary;
 }
 bitset<64> tmp = output;
 for(int i=0; i<32; ++i)
 output[31-i] = tmp[32-P[i]];          //Permutation P to reorder the C
 return output;
}

bitset<56> leftShift(bitset<56> left, bitset<56> right, int shift) //shift is a array to show how many bit we should shift left in this round.
{ bitset<56> a=0xFFFFFFF;   //because I use 56 bitset to store left and right, not 28. So during left shift, there will bit be shifted into 29,30 position, I use a to delete them
 bitset<56> tmp1 = left;
 bitset<56> tmp2 = right;
bitset<56> subkey;
int i=28-shift;
left=(tmp1<<shift| tmp1>>i) & a; //first x bit will add to last position, than shift other bit left x postion. use a to delete overshift
right=(tmp2<<shift| tmp2>>i) & a;
 
 subkey=left<<28 | right;   //only two 56 bitset can be combine into one 56 bitset, that is the reason I use 56 bit in left and right
 return subkey;
}
void generateKeys() //generate 16 56-bit subkeys
{
 bitset<56> PC01;
 bitset<56> left; //the reason I use 56 instead of 28 will be shown in function: leftShift
 bitset<56> right;
 bitset<48> PC02;
 for (int i=0; i<56; ++i) //using table PC-1 to generate a 56-bit key
 PC01[55-i] = key[64 - PC_1[i]]; //the same as f function's expansion

 for(int round=0; round<16; ++round) //16 round need different subkey
 {

 for(int i=28; i<56; ++i) //Divide PC-1 result into left C and right D two 28 length key
 left[i-28] = PC01[i]; //when we don't need to get the postion i of a string, but just copy a bitset to another, left[0-27]=PC01[28-55]
 for(int i=0; i<28; ++i)
 right[i] = PC01[i]; //right[0-27]=PC01[0-27]
 PC01 = leftShift(left, right , shiftBits[round]); //LEFT circular shift, get the new left and right and comebine them together
 for(int i=0; i<48; ++i)
 PC02[47-i] = PC01[56 - PC_2[i]]; //just like the algorithm we generate PC-1 result, use another table, PC-2 generate the final subkey of each round.
 subkey[round] = PC02;
 }
}
 bitset<64> StringtoBinary(string s)
{ unsigned long long PC10;
 bitset<64> bits;
 stringstream ss;
 ss.str(s);             //the content of string is the hex format of key/plaintext
 ss>>hex>>PC10;            //change hex format to decimal format
bits = bitset<64>(PC10);       //change decimal format to binary format
 return bits;
}

bitset<64> encrypt(bitset<64>& plaintext)
{
 bitset<64> ciphertext;
 bitset<64> IP_result;
 bitset<64> left;
 bitset<64> right;
 bitset<64> newLeft;
 for(int i=0; i<64; ++i)
 IP_result[63-i] = plaintext[64-IP[i]]; //permutation plaintext by IP table, algorithm just like PC-1, PC-2
 for(int i=32; i<64; ++i)
 left[i-32] = IP_result[i];            //divide IP result into two 32 bit sub-plaintext (L and R)
 for(int i=0; i<32; ++i)
 right[i] = IP_result[i];
 for(int round=0; round<16; ++round)
 {
 newLeft = right;                                  //in each round, the input of left is the last round right result;
 right = left ^ f(right,subkey[round]);           //the output of right is the last round left XOR f(last round right, subkey of this round);
 left = newLeft;                                    //the output of left is the last round right;
 }
 ciphertext=right<<32 | left;                      //combine left and right, but this time right first than left!!! R and L
 IP_result = ciphertext;
 for(int i=0; i<64; ++i)
 ciphertext[63-i] = IP_result[64-IP_1[i]];                 //using last permutation IP-1 to get the final ciphertext.
 return ciphertext;
}
 
int main() {
 string k1 = "8E71CF39";
 string k2 = "E73C9EF0";
 string s1 = "37FEC937";
 string s2 = "EC817E0F";

 plaintext=StringtoBinary(s1)<<32 | StringtoBinary(s2);               //plaintext is the binary format of s1s2 "37FEC937EC817E0F"
 key=StringtoBinary(k1)<<32 | StringtoBinary(k2);                       //plaintext is the binary format of k1k2 "8E71CF39E73C9EF0"
 generateKeys();

 ciphertext = encrypt(plaintext);
 cout<<ciphertext<<endl;
 return 0;
} 

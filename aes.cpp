#include <iostream>
#include <valarray>
#include <bitset>
using namespace std;

//The following arrays are the lookup tables for the subBytes step and its inverse
//source for the Rijndael S-Box: www.giac.org/cissp-papers/42.pdf
unsigned int  s[256] = 
{
   0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
   0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
   0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
   0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
   0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
   0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
   0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
   0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
   0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
   0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
   0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
   0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
   0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
   0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
   0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
   0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
};

unsigned int  inv_s[256] = {
   0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
   0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
   0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
   0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
   0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
   0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
   0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
   0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
   0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
   0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
   0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
   0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
   0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
   0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
   0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
   0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
};

//Function to print the contents of a valarray in hex format
//This allows us to show the progress at each step of the cipher
void printMessage( valarray<int>  input, int numElements, bool print = true){
  if(print){
    for(int i = 0; i < numElements; i++){
      cout<< hex << (int) input[i] << " ";
    }
    std::cout<<std::endl;
  }
}

//Function to print the contents of a valarray in character format
//This allows us to show the final result of the cipher
void printMessageText( valarray<int>  input, int numElements){
  for(int i = 0; i < numElements; i++){
    cout <<  (char) input[i];
  }
  std::cout<<std::endl;

}

//Helper function to get the digits of a hex number for lookup in the
//     subBytes table
void intToHex(unsigned int a, unsigned int& column, unsigned int& row){ 
  unsigned int sixteens = a/16;
  unsigned int ones = a - (sixteens * 16);
  row = sixteens;
  column = ones;
}


//subBytes step
//take first hex digit and look up column in s-box, use second to look for row
void subBytes(valarray<int>  input, valarray<int>&  output, int numElements, bool print = true){
  unsigned int columns = 0, rows = 0;
  for(int i = 0; i < numElements; i++ ){
    intToHex(input[i], columns, rows);    
    output[i] = s[rows * 16 + columns];
  }
  if(print)
    cout<<"new state matrix"<<endl;
  printMessage(output[slice(0, 4, 4)], 4, print);
  printMessage(output[slice(1, 4, 4)], 4, print);
  printMessage(output[slice(2, 4, 4)], 4, print);
  printMessage(output[slice(3, 4, 4)], 4, print);
  cout<<endl;

}

//inverse subBytes step
void invSubBytes(valarray<int>  input, valarray<int>&  output, int numElements, bool print = true){
  unsigned int columns = 0, rows = 0;
  for(int i = 0; i < numElements; i++ ){
    
    intToHex(input[i], columns, rows);  
    output[i] = inv_s[rows * 16 + columns];
  }
  cout<<"new state matrix"<<endl;
  printMessage(output[slice(0, 4, 4)], 4);
  printMessage(output[slice(1, 4, 4)], 4);
  printMessage(output[slice(2, 4, 4)], 4);
  printMessage(output[slice(3, 4, 4)], 4);
  cout<<endl;
}

//Helper function to do left-circular rotation. This is used in several steps,
//     including the shiftRows step.
valarray<int> rotl(valarray<int>  input, int amount){
  valarray<int>  temp (4);
  for(int i = 0; i < amount; i++){
    //rotate the array input so that:
    //0 1 2 3
    //becomes:
    //1 2 3 0

    temp[0] = input[1];
    temp[1] = input[2];
    temp[2] = input[3];
    temp[3] = input[0];
    for(int i = 0; i<4; i++) input[i] = temp[i];
  }
  return input;
}

//inverse of the left-circular rotation; a right-circular rotation. Used in the
//     inverse shiftRows step
valarray<int> rotr(valarray<int>  input, int amount){
  valarray<int>  temp (4);
  for(int i = 0; i < amount; i++){
    //rotate the array input so that:
    //0 1 2 3
    //becomes:
    //3 0 1 2

    temp[0] = input[3];
    temp[1] = input[0];
    temp[2] = input[1];
    temp[3] = input[2];
    for(int i = 0; i<4; i++) input[i] = temp[i];
  }
  return input;
}

//galois multiplication, used in the mixColumns step
//used for reference: http://www.samiam.org/galois.html
int mult(int a, int b){
  bitset<8> x = (bitset<8>) a;
  bitset<8> y = (bitset<8>) b;
  bitset<8> p;

  bool setToOne = false;

  for(int i = 0; i < 8; i++){

    //if the smallest bit of y is set,
    //  XOR p and a
    
    if(y[0] == 1){
      p ^= x;
    }
  
    //is the largest bit of x set?
    if(x[7] == 1){
      setToOne = true;
    } else{
      setToOne = false;
    }

    //shift to the left, discarding the largest bit
    x = x<<1;

    //if the high bit of x was set, XOR with the constant 0x1b
    if(setToOne){
      x ^= 0x1b;
    }
    //shift to the right, discarding the lowest bit
    y = y >> 1;
  }
  

  return p.to_ulong();
}

//helper function to apply the galois matrix multiplication
int matProd(valarray<int> c, unsigned int r[4]){
  int output = 0;
  for(int i = 0; i< 4; i++){
    output =  output ^ mult(c[i],  r[i]);
  }
  return output;
}

//mixcolumns step
void mixColumns(valarray<int> input, valarray<int>& output, bool print = true){
  valarray<int> c1 = input[slice(0, 4, 1)];
  valarray<int> c2 = input[slice(4, 4, 1)];
  valarray<int> c3 = input[slice(8, 4, 1)];
  valarray<int> c4 = input[slice(12, 4, 1)];

  
  unsigned int r1[4] = {2, 3, 1, 1};
  unsigned int r2[4] = {1, 2, 3, 1};
  unsigned int r3[4] = {1, 1, 2, 3};
  unsigned int r4[4] = {3, 1, 1, 2};
  unsigned int *r[4];
  r[0] = r1;
  r[1] = r2;
  r[2] = r3;
  r[3] = r4;

  
  for(int i = 0; i < 4; i++){ //row
    for(int j = 0 ; j < 4; j++){ //column
      output[j * 4 + i] = matProd(input[slice(j*4, 4, 1)], r[i]);
    }
  }

    if(print)
    cout<<"new state matrix"<<endl;
  printMessage(output[slice(0, 4, 4)], 4, print);
  printMessage(output[slice(1, 4, 4)], 4, print);
  printMessage(output[slice(2, 4, 4)], 4, print);
  printMessage(output[slice(3, 4, 4)], 4, print);
  cout<<endl;

  
}

//inverse mixcolumns step
void invMixColumns(valarray<int> input, valarray<int>& output, bool print = true){
  valarray<int> c1 = input[slice(0, 4, 1)];
  valarray<int> c2 = input[slice(4, 4, 1)];
  valarray<int> c3 = input[slice(8, 4, 1)];
  valarray<int> c4 = input[slice(12, 4, 1)];

  
  unsigned int r1[4] = {0x0E, 0x0B, 0x0D, 0x09};
  unsigned int r2[4] = {0x09, 0x0E, 0x0B, 0x0D};
  unsigned int r3[4] = {0x0D, 0x09, 0x0E, 0x0B};
  unsigned int r4[4] = {0x0B, 0x0D, 0x09, 0x0E};
  unsigned int *r[4];
  r[0] = r1;
  r[1] = r2;
  r[2] = r3;
  r[3] = r4;

  
  for(int i = 0; i < 4; i++){ //row
    for(int j = 0 ; j < 4; j++){ //column
      output[j * 4 + i] = matProd(input[slice(j*4, 4, 1)], r[i]);
    }
  }

    if(print)
    cout<<"new state matrix"<<endl;
  printMessage(output[slice(0, 4, 4)], 4, print);
  printMessage(output[slice(1, 4, 4)], 4, print);
  printMessage(output[slice(2, 4, 4)], 4, print);
  printMessage(output[slice(3, 4, 4)], 4, print);
  cout<<endl;

  
}


//shiftRows step
void shiftRows(valarray<int>  input, valarray<int>&  output, bool print = true){
  
  for(int i = 0; i<4; i++){
    output[slice(i,4,4)] = input[slice(i, 4, 4)];
    output[slice(i,4,4)] = rotl(output[slice(i,4,4)], i);
  }

    if(print)
    cout<<"new state matrix"<<endl;
  printMessage(output[slice(0, 4, 4)], 4, print);
  printMessage(output[slice(1, 4, 4)], 4, print);
  printMessage(output[slice(2, 4, 4)], 4, print);
  printMessage(output[slice(3, 4, 4)], 4, print);
  cout<<endl;

}

//inverse shiftRows
void invShiftRows(valarray<int>  input, valarray<int>&  output, bool print = true){
  for(int i = 0; i<4; i++){
    output[slice(i,4,4)] = input[slice(i, 4, 4)];
    output[slice(i,4,4)] = rotr(output[slice(i,4,4)], i);
  }

    if(print)
    cout<<"new state matrix"<<endl;
  printMessage(output[slice(0, 4, 4)], 4, print);
  printMessage(output[slice(1, 4, 4)], 4, print);
  printMessage(output[slice(2, 4, 4)], 4, print);
  printMessage(output[slice(3, 4, 4)], 4, print);
  cout<<endl;

}

//Add Round Key step
void addRoundKey(valarray<int>& message, valarray<int> roundkeys, int round, bool print = true){
  valarray<int> rKey = roundkeys[slice(16*round, 16, 1)];
  for(int i = 0; i < 16; i++) message[i] = message[i] ^ rKey[i];
    cout<<"new state matrix"<<endl;
  printMessage(message[slice(0, 4, 4)], 4);
  printMessage(message[slice(1, 4, 4)], 4);
  printMessage(message[slice(2, 4, 4)], 4);
  printMessage(message[slice(3, 4, 4)], 4);
  cout<<endl;

}

//generate round keys
// from the original 128-bit key, generate 10 more keys (for 11 total)
void genRoundKeys(valarray<int>  input, valarray<int>&  output, bool print = true){
  valarray<int>  w0 (4), w1 (4), w2 (4), w3 (4), w4 (4), w5 (4), w6 (4), w7 (4);

  valarray<int> temp (4);

  for(int i = 0; i<176; i++) output[i] = 0;
  for(int i = 0; i<16; i++) output[i] = input[i];

  for(int j = 1; j < 11; j++){

  
    //the first 4 sub-arrays are taken from the original key
    w0 = output[slice(((j-1)*16) + 0, 4, 1)];
    w1 = output[slice(((j-1)*16) + 4, 4, 1)];
    w2 = output[slice(((j-1)*16) + 8, 4, 1)];
    w3 = output[slice(((j-1)*16) + 12, 4, 1)];

    //The 5th sub-array is created as a function of the first and fourth sub-arrays
    // w4 = w0 XOR g(w3)
    for(int i = 0; i< 4; i++) temp[i] = w3[i];
    
    //These three operations represent g(w3)
    temp = rotl(temp, 1);
    subBytes(temp, temp, 4, false);
    
    int rcon;
    switch(j){
    case 1: rcon = 0x01; break; 
    case 2: rcon = 0x02; break; 
    case 3: rcon = 0x04; break; 
    case 4: rcon = 0x08; break; 
    case 5: rcon = 0x10; break; 
    case 6: rcon = 0x20; break; 
    case 7: rcon = 0x40; break; 
    case 8: rcon = 0x80; break; 
    case 9: rcon = 0x1b; break; 
    case 10: rcon = 0x36; break; 
    case 11: rcon = 0x6c; break; 
    }

    temp[0] = temp[0] ^ rcon;

    //This step represents w0 XOR g(w3)
    for(int i = 0; i< 4; i++ ) w4[i] = w0[i] ^ temp[i];
  
    //w5 = w1 XOR w4
    for(int i = 0; i< 4; i++ ) w5[i] = w1[i] ^ w4[i];
    //w6 = w2 XOR w5
    for(int i = 0; i< 4; i++ ) w6[i] = w2[i] ^ w5[i];
    //w7 = w3 XOR w6
    for(int i = 0; i< 4; i++ ) w7[i] = w3[i] ^ w6[i];
  
    output[slice((j*16) + 0,4,1)] = w4[slice(0,4,1)];
    output[slice((j*16) + 4,4,1)] = w5[slice(0,4,1)];
    output[slice((j*16) + 8,4,1)] = w6[slice(0,4,1)];
    output[slice((j*16) + 12,4,1)] = w7[slice(0,4,1)];
  }
  std::cout << "input key"<<std::endl;
  printMessage(input, 16);
  std::cout << "output keys"<<std::endl;
  
  for(int i = 0; i < 11; i++){
    printMessage(output[slice(i*16, 16, 1)], 16);
  }

}



int main(int argc, char* argv[]){
  valarray<int>  input (16);
  valarray<int>  output (16);
  valarray<int>  final (16);
  valarray<int>  mixed (16);
  valarray<int>  message (16);
  valarray<int>  outMessage (16);
  valarray<int> key (16);
  valarray<int> roundkeys (176);

  char userInput = 'y';

  string k1;
  string m1;

  
  cout<<"input 16 character key"<<endl;
  cout<<"16 characters is this many:"<<endl<<"________________"<<endl;

  getline(std::cin, k1);

  cout<<"input 16 character message"<<endl;
  cout<<"16 characters is this many:"<<endl<<"________________"<<endl;

  getline(std::cin, m1);

  for(int i = 0; i<16; i++) message[i] = m1[i];
  for(int i = 0; i<16; i++) key[i] = k1[i];


  /********************
   * Begin Encryption *
   ********************/
  genRoundKeys(key, roundkeys);

  std::cout << endl << "original message:"<<std::endl;
  printMessage(message, 16);
  cout<<endl;

  std::cout << "add round 0 key"<<std::endl;
  valarray<int> rKey = roundkeys[slice(0, 16, 1)];
  for(int i = 0; i < 16; i++) message[i] = message[i] ^ rKey[i];
  printMessage(message[slice(0, 4, 4)], 4);
  printMessage(message[slice(1, 4, 4)], 4);
  printMessage(message[slice(2, 4, 4)], 4);
  printMessage(message[slice(3, 4, 4)], 4);
  cout<<endl;



  for(int numRounds = 0; numRounds < 10; numRounds++){
    std::cout << endl << "byte substitution"<<std::endl;
    subBytes(message, message, 16);
    
    cout<<endl;
    
    std::cout << "shift rows"<<std::endl;
    shiftRows(message, message);
    
    cout<<endl;

  
    if(numRounds != 9){
      std::cout << "mix columns"<<std::endl;
      mixColumns(message, message);
      cout<<endl;
    }
    
    
    std::cout << "xor with roundKey "<<numRounds + 1<<endl;;
    addRoundKey(message, roundkeys, numRounds + 1);
    cout<<endl;

    if(numRounds != 9){
      cout<< "output from round "<< numRounds + 1<<endl;
      printMessage(message[slice(0, 4, 4)], 4);
      printMessage(message[slice(1, 4, 4)], 4);
      printMessage(message[slice(2, 4, 4)], 4);
      printMessage(message[slice(3, 4, 4)], 4);
      cout<<endl;
    }
    
  }

  cout<< "final state matrix:"<<endl;
  printMessage(message[slice(0, 4, 4)], 4);
  printMessage(message[slice(1, 4, 4)], 4);
  printMessage(message[slice(2, 4, 4)], 4);
  printMessage(message[slice(3, 4, 4)], 4);
  cout<<endl;

  cout<< "final ciphertext:"<<endl;
  printMessage(message, 16);


  cout<<endl<<"Do you want to decrypt the ciphertext? (y/n)"<<endl<<endl;
  cin>>userInput;
  if(userInput == 'y'){

  /********************
   * Begin Decryption *
   ********************/
  
    for(int numRounds = 9; numRounds >= 0; numRounds--){
      cout<< "add roundkey "<< numRounds + 1 << endl;
      addRoundKey(message, roundkeys, numRounds+1);
      if(numRounds != 9){
	cout<< "inverse mix columns" <<endl;
	invMixColumns(message, message);
      }
    
      cout<< "inverse shift rows" <<endl;
      invShiftRows(message, message);
      std::cout << "inverse sub bytes"<<std::endl;
      invSubBytes(message, message, 16);
    
    }
    cout<<"add roundkey 0"<<endl;
    addRoundKey(message, roundkeys, 0);

    cout<< "final plaintext:"<<endl;
    printMessageText(message, 16);
  }
  return 0;
}


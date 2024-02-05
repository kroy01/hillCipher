//============================================================================
// Name        : DES_alg_CipherText.cpp
// Author      : Krishnendu Roy_21BCE3733
// Version     :
// Copyright   : Your copyright notice
// Description : DES algorithm implementation in C++, Ansi-style
//============================================================================


#include <iostream>
#include <vector>
#include <string>
#include <bitset>
#include <math.h>
#include <bits/stdc++.h>
#include <numeric>
#include <algorithm>
using namespace std;







//TABLES USED FOR DES ALGORITHMS


//INITIAL PERMUTATION(IP)
const int IP[] = {58,50,42,34,26,18,10,2,
				 60,52,44,36,28,20,12,4,
				 62,54,46,38,30,22,14,6,
				 64,56,48,40,32,24,16,8,
				 57,49,41,33,25,17,9,1,
				 59,51,43,35,27,19,11,3,
				 61,53,45,37,29,21,13,5,
				 63,55,47,39,31,23,15,7};


//INVERSE INITIAL PERMUTATION(IP^-1)
const int IP_INV[] = {40,8,48,16,56,24,64,32,
					 39,7,47,15,55,23,63,31,
					 38,6,46,14,54,22,62,30,
					 37,5,45,13,53,21,61,29,
					 36,4,44,12,52,20,60,28,
					 35,3,43,11,51,19,59,27,
					 34,2,42,10,50,18,58,26,
					 33,1,41,9,49,17,57,25};


//EXPANSION PERMUTATION(E)
const int EP[] = {32,1,2,3,4,5,
				 4,5,6,7,8,9,
				 8,9,10,11,12,13,
				 12,13,14,15,16,17,
				 16,17,18,19,20,21,
				 20,21,22,23,24,25,
				 24,25,26,27,28,29,
				 28,29,30,31,32,1};


//PERMUTATION FUNCTION(P)
const int PF[] = {16,7,20,21,29,12,28,17,
					1,15,23,26,5,18,31,10,
					2,8,24,14,32,27,3,9,
					19,13,30,6,22,11,4,25};

//INPUT KEY
const int IK[] = {1,2,3,4,5,6,7,
					9,10,11,12,13,14,15,
					17,18,19,20,21,22,23,
					25,26,27,28,29,30,31,
					33,34,35,36,37,38,39,
					41,42,43,44,45,46,47,
					49,50,51,52,53,54,55,
					57,58,59,60,61,62,63};


//PERMUTED CHOICE ONE (PC-1)
const int PC_1[] = {57,49,41,33,25,17,9,
					1,58,50,42,34,26,18,
					10,2,59,51,43,35,27,
					19,11,3,60,52,44,36,
					63,55,47,39,31,23,15,
					7,62,54,46,38,30,22,
					14,6,61,53,45,37,29,
					21,13,5,28,20,12,4};


//PERMUTED CHOICE TWO(PC-2) [used for key compression from 58 bits to 48 bits
const int PC_2[] = {14,17,11,24,1,5,3,28,
					15,6,21,10,23,19,12,4,
					26,8,16,7,27,20,13,2,
					41,52,31,37,47,55,30,40,
					51,45,33,48,44,49,39,56,
					34,53,46,42,50,36,29,32};


//SCHEDULE OF LEFT SHIFTS ACROSS 16 ROUNDS
const int SLS[] = {1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1};



//S-BOX TABLE
const int SBOX[][4][16] = {{{14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7},
							 {0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8},
							 {4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0},
							 {15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13}},

							 {{15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10},
							 {3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5},
							 {0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15},
							 {13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9}},

							 {{10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8},
							 {13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1},
							 {13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7},
							 {1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12}},

							 {{7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15},
							 {13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9},
							 {10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4},
							 {3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14}},

							 {{2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9},
							 {14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6},
							 {4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14},
							 {11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3}},

							 {{12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11},
							 {10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8},
							 {9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6},
							 {4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13}},

							 {{4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1},
							 {13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6},
							 {1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2},
							 {6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12}},

							 {{13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7},
							 {1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2},
							 {7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8},
							 {2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11}}};




//FOR CONVERTING TEXT TO BLOCKS OF 64 BITS(PADDING LAST BLOCK IF BITS NOT AVAILABLE IN MULTIPLES OF 64)


//CONVERTING TEXT TO BINARY(EACH CHAR REPRESENTED BY 8 BITS)
std::string textToBinary(std::string str)//const &
{
	 std::string binary = "";
	 for(int i=0; i<str.length(); i++){//for (char c: str) {//const &
		 //binary += std::bitset<8>(c).to_string();// + ' ';
		 binary+=std::bitset<8>(str[i]).to_string();
 }
 return binary;
}


//ADDING EXTRA BITS IF NEEDED TO MAKE TOTAL NO OF BITS MULTIPLE OF 64
std::string bitPadding(std::string str)
{
	std::string paddedBinary=str;
	int count = str.length();
	if(count%64 != 0)
		{
		while(count%64 != 0)
		{
			paddedBinary+="00000000";
			count+=8;
		}
	}
	return paddedBinary;
}


//SEGMENTING THE BIT STRING TO BLOCKS OF 64 BITS EACH TO BE PROCESSED FOR DES ALGORITHM
std::vector <string> stringSegmentation(std::string str)
{
	std::vector <string> v;
	for(int i=0; i<str.length(); i++)
	{
		std::string ss = "";
		int count = 0;
		while(count!=64)
		{
			ss+=str[i];
			count++;
			i++;
		}
		v.push_back(ss);
		i--;
	}
	return v;
}


//FUNCTIONS TO BE USED ON THE 64 BIT KEY FOR DES ALGORITHM

//FOR CHECKING CONDITIONS ON KEY (IT SHOULD BE 8 BYTES LONG AND BE REPRESENTED IN HEXCODE DURING INPUT)
bool checkKey(std::string key)
{
	if(key.length() != 16)//in hexcode each character represents 4 bits , hence 16*4 = 64 bits = 8 bytes
	{
		return false;
	}else
	{
		bool flag = true;
		std::string hex = "ABCDEF0123456789";
		for(int i=0; i<key.length(); i++)
		{
			flag = (hex.find(key[i]) != string::npos);
			if(!flag)
			{
				break;
			}
		}
		return flag;
	}
}



//FOR CONVERTING HEXCODE KEY TO BINARY KEY
std::string keyToBinary(std::string key)
{
	std::string BinaryKey = "";
	for(char c : key)
	{
		switch(c)
		{
			case '0' : BinaryKey+="0000"; break;
			case '1' : BinaryKey+="0001"; break;
			case '2' : BinaryKey+="0010"; break;
			case '3' : BinaryKey+="0011"; break;
			case '4' : BinaryKey+="0100"; break;
			case '5' : BinaryKey+="0101"; break;
			case '6' : BinaryKey+="0110"; break;
			case '7' : BinaryKey+="0111"; break;
			case '8' : BinaryKey+="1000"; break;
			case '9' : BinaryKey+="1001"; break;
			case 'A' : BinaryKey+="1010"; break;
			case 'B' : BinaryKey+="1011"; break;
			case 'C' : BinaryKey+="1100"; break;
			case 'D' : BinaryKey+="1101"; break;
			case 'E' : BinaryKey+="1110"; break;
			case 'F' : BinaryKey+="1111"; break;
			default : BinaryKey+=""; break;
		}
	}
	return BinaryKey;
}


//FOR THE 64 BIT KEY INPUT(INPUT SHOULD BE IN HEXCODE)
std::string keyInput()
{
	bool flag = false;
	std::string key;
	cout<<"enter key : ";
	cin>>key;
	flag = checkKey(key);
	if(!flag)
	{
		while(!flag)
		{
			cout<<"key input not in hex/no of char not equal to 8\nenter key again : ";
			cin>>key;
			flag=checkKey(key);
		}
	}
	return keyToBinary(key);
}



//FUNCTIONS USED FOR PERFORMING PERMUTATIONS ON KEY AND PLAIN TEXT


//FOR DETERMINING THE i AND j INDEX OF THE S-BOX
int sbox_ijValues(std::string str,int a)
{
	 int x;
	 if(a == 2)
	 {
		 if(str == "00") {x = 0;}
		 else if(str == "01") {x = 1;}
		 else if(str == "10") {x = 2;}
		 else if(str == "11") {x = 3;}
		 else { x=-1;}
	 }
	 else if(a == 4)
	 {
		 if(str == "0000") {x = 0;}
		 else if(str == "0001") {x = 1;}
		 else if(str == "0010") {x = 2;}
		 else if(str == "0011") {x = 3;}
		 else if(str == "0100") {x = 4;}
		 else if(str == "0101") {x = 5;}
		 else if(str == "0110") {x = 6;}
		 else if(str == "0111") {x = 7;}
		 else if(str == "1000") {x = 8;}
		 else if(str == "1001") {x = 9;}
		 else if(str == "1010") {x = 10;}
		 else if(str == "1011") {x = 11;}
		 else if(str == "1100") {x = 12;}
		 else if(str == "1101") {x = 13;}
		 else if(str == "1110") {x = 14;}
		 else if(str == "1111") {x = 15;}
		 else { x=-1;}
	 }
	 return x;
}


//FOR CONVERTING THE VALUE CHOSEN FROM S-BOX TO 4 BIT BINARY STRING
std::string sboxOutput(int x)
{
	std::string sbo = "";
	switch(x)
	{
		case 0 : sbo += "0000"; break;
		case 1 : sbo += "0001"; break;
		case 2 : sbo += "0010"; break;
		case 3 : sbo += "0011"; break;
		case 4 : sbo += "0100"; break;
		case 5 : sbo += "0101"; break;
		case 6 : sbo += "0110"; break;
		case 7 : sbo += "0111"; break;
		case 8 : sbo += "1000"; break;
		case 9 : sbo += "1001"; break;
		case 10 : sbo += "1010"; break;
		case 11 : sbo += "1011"; break;
		case 12 : sbo += "1100"; break;
		case 13 : sbo += "1101"; break;
		case 14 : sbo += "1110"; break;
		case 15 : sbo += "1111"; break;
		default : sbo += ""; break;
	}
	return sbo;
}



//FOR PERFORMING PERMUTATION BASED ON VARIOUS TABLES
std::string permute(std::string str, std::string code )
{
	std::string strn = "";
	if(code == "IP")
	{
		//vector <std::string> v;
		//v.push_back("");
		for(int i = 0; i<(int)(sizeof(IP)/sizeof(IP[0])); i++)
		{
			//v[0]+=str[IP[i]-1];
			//cout<<str[IP[i]-1]<<endl;
			strn+=str[IP[i]-1];
		}
		//for(int i=0; i<v.size();i++)
		//{
			//strn += v[i];
		//}
		//strn = v[0];
	}
	else if(code == "IP_INV")
	{
		for(int i = 0; i<sizeof(IP_INV)/sizeof(IP_INV[0]); i++)
		{
			strn+=str[IP_INV[i]-1];
		}
	}
	else if(code == "EP")
	{
		for(int i = 0; i<sizeof(EP)/sizeof(EP[0]); i++)
		{
			strn+=str[EP[i]-1];
		}
	}
	else if(code == "IK")
	{
		for(int i = 0; i<sizeof(IK)/sizeof(IK[0]); i++)
		{
			strn+=str[IK[i]-1];
		}
	}
	else if(code == "PC_1")
	{
		for(int i = 0; i<sizeof(PC_1)/sizeof(PC_1[0]); i++)
		{
			strn+=str[PC_1[i]-1];
		}
	}
	else if(code == "PC_2")
	{
		for(int i = 0; i<sizeof(PC_2)/sizeof(PC_2[0]); i++)
		{
			strn+=str[PC_2[i]-1];
		}
	}
	else if(code == "SBOX")
	{
		std::vector <string> v;
		for(int i=0; i<str.length(); i++)
		{
			std::string ss = "";
			int count = 0;
			while(count!=6)
			{
				ss+=str[i];
				count++;
				i++;
			}
			v.push_back(ss);
			i--;
			//cout<<"\ncount = "<<count<<endl;
		}
		for(int k = 0; k<v.size(); k++)
		{
			//cout<<"\nk = "<<k<<endl;
			std::string bit6Block = v[k];
			//cout<<"6bit = "<<bit6Block<<endl;
			std::string bit2part = "";
			bit2part = bit6Block[0];//bit2part = bit6Block[0] + bit6Block[5] does not work
			bit2part += bit6Block[5];
			//cout<<"2bit = "<<bit2part<<endl;
			std::string bit4part = "";
			bit4part = bit6Block[1];//bit4part = bit6Block[1] + bit6Block[2] + bit6Block[3] + bit6Block[4] does not work
			bit4part += bit6Block[2];
			bit4part += bit6Block[3];
			bit4part += bit6Block[4];
			//cout<<"4bit = "<<bit4part<<endl;
			int i = sbox_ijValues(bit2part,2); //cout<<"i = "<<i<<endl;
			int j = sbox_ijValues(bit4part,4);//cout<<"j = "<<j<<endl;
			strn += sboxOutput(SBOX[k][i][j]);
		}
	}
	else if(code == "PF")
	{
		for(int i = 0; i<sizeof(PF)/sizeof(PF[0]); i++)
		{
			strn+=str[PF[i]-1];
		}
	}
	return strn;
}



void swapstr(std::string *s1, std::string *s2)
{
	std::string st = *s1;
	*s1 = *s2;
	*s2 = st;
}


//FOR PERFORMING XOR ON TWO BINARY STRINGS OF EQUAL LENGTH
std::string xor_bs(std::string s1, std::string s2, int x)
{
	std::string str = "";
	if (x == 48)
	{
		for(int i=0; i<48; i++)
		{
			if(s1[i] == s2[i])
			{
				str += "0";
			}
			else
			{
				str += "1";
			}
		}
	}
	else if (x == 32)
	{
		for(int i=0; i<32; i++)
		{
			if(s1[i] == s2[i])
			{
				str += "0";
			}
			else
			{
				str += "1";
			}
		}
	}
	return str;
}



//FOR IMPLEMENTING ONE ROUND OF DES ALGORITHM

//FUNCTONS FOR OPERATIONS ON KEY IN DES ALGORITHM IN EACH ROUND


//FOR LEFT CIRCULAR SHIFT OF STRING (SUB_STRINGS OF 28-BITS EACH FROM PREV ROUND 56-BIT KEY)
std::string lcs(std::string str, int round)
{
	int nolcs = SLS[round];
	std::string stro = str;
	std::string strn = "";
	for(int i=0; i<nolcs; i++)
	{
		strn = "";
		for(int j=1; j<stro.length(); j++)
		{
			strn+=stro[j];
		}
		strn+=stro[0];
		stro = strn;
	}
	return strn;
}


//FOR SUBKEY GENERATION
std::string subKeyGenerator(std::string prevKeyLeft, std::string prevKeyRight, int round)
{
	std::string subKey = "";

	std::string nextKeyLeft = lcs(prevKeyLeft,round);
	std::string nextKeyRight = lcs(prevKeyRight,round);

	std::string nextKey = nextKeyLeft + nextKeyRight;

	subKey = permute(nextKey, "PC_2");

	return subKey;
}





//FOR F_FUNCTION(CIPHER_FUNCTION)
/*F FUNCTION TAKES
1) RIGHT SUB_STRING(32 BIT) R_(i-1) OF THE PREVIOUS ROUND MODIFIED 64 BIT BLOCK OF THE INTERMEDIATE CIPHER TEXT; AND
2) SUB KEY GENERATED IN CURRENT ROUND

F FUNCTION GIVES :
	A 32 BIT STRING AS OUTPUT
*/
std::string f_function(std::string R_prev, std::string subKey_current)
{
	std::string output_32bit = "";

	std::string R_prev_expanded = "";
	R_prev_expanded = permute(R_prev, "EP");//32bit->48bit
	//cout<<"ebox : "<<R_prev_expanded<<endl;

	std::string out_temp = "";
	out_temp = xor_bs(R_prev_expanded,subKey_current,48);
	//cout<<out_temp<<endl;

	out_temp = permute(out_temp,"SBOX");//48bit->32bit
	//cout<<out_temp<<endl;

	output_32bit = permute(out_temp,"PF");
	//cout<<output_32bit<<endl;

	return output_32bit;
}



//FOR GENERATING CURRENT R_i IN CURRENT ROUND
std::string generate_R(std::string L_prev, std::string f_function_output)
{
	std::string R_current = "";

	R_current = xor_bs(L_prev, f_function_output, 32);

	return R_current;
}


//FOR GENERATING CURRENT L_i IN CURRENT ROUND
std::string generate_L(std::string R_prev)
{
	std::string L_current = "";

	L_current = R_prev;

	return L_current;
}


//FOR GENERATING CURRENT KL_i IN CURRENT ROUND
std::string generate_KL(std::string KL_prev, int round)
{
	std::string KL_current = "";

	KL_current = lcs(KL_prev,round);

	return KL_current;
}


//FOR GENERATING CURRENT KR_i IN CURRENT ROUND
std::string generate_KR(std::string KR_prev, int round)
{
	std::string KR_current = "";

	KR_current = lcs(KR_prev,round);

	return KR_current;
}


//FOR PERFORMING THE ROUND
void round(std::string *L_prev, std::string *R_prev, std::string *KL_prev, std::string *KR_prev, int round_num)
{
	std::string l_prev = *L_prev;
	std::string r_prev = *R_prev;
	std::string kl_prev = *KL_prev;
	std::string kr_prev = *KR_prev;

	std::string subKey_current = subKeyGenerator(l_prev, r_prev, round_num);

	*L_prev = generate_L(r_prev);
	*R_prev = generate_R(l_prev, f_function(r_prev,subKey_current));

	*KL_prev = generate_KL(kl_prev,round_num);
	*KR_prev = generate_KR(kr_prev,round_num);

}

//PERFORMING ROUNDS 16 TIMES [FINAL CODE FUNCTION][FOR SENDER] ONE BLOCK
std::string des_sender_64bitBlock(std::string text, std::string key)
{
	std::string *text_p = new std::string;//to tackle std::bad_alloc separate memory assigned during compile time

	*text_p = permute(text,"IP");

	std::string text_sub_l = "";
	std::string text_sub_r = "";

	for(int i=0; i<32; i++)
	{
		text_sub_l += (*text_p)[i];
		text_sub_r += (*text_p)[i+32];
	}

	//std::string key_reduced = permute(key, "IK");//no need to call IK as PC_1 reduces along with permuting the 64bit input key

	std::string key_reduced = permute(key, "PC_1");

	std::string key_sub_l = "";
	std::string key_sub_r = "";

	for(int i=0; i<28; i++)
	{
		key_sub_l += key_reduced[i];
		key_sub_r += key_reduced[i+28];
	}


	for(int i=0; i<16; i++)
	{

		round(&text_sub_l, &text_sub_r, &key_sub_l, &key_sub_r, i);
	}
	//cout<<"test = "<<endl;
	swapstr(&text_sub_l, &text_sub_r);


	std::string *cipherText = new std::string;//to tackle std::bad_alloc separate memory assigned during compile time
	//std::string cipherText = "";
	*cipherText="";

	*cipherText = text_sub_l;
	*cipherText += text_sub_r;
	//cout<<"test = "<<endl;


	*cipherText = permute(*cipherText, "IP_INV");

	return *cipherText;
}

std::string des_encrypt(std::string text, std::string key)
{
	std::string *tb = new std::string;
	std::string *bp = new std::string;

	*tb = textToBinary(text);
	*bp = bitPadding(*tb);

	vector <std::string> *sb = new  vector <std::string>;

	*sb = stringSegmentation(*bp);


	std::string *cipher = new std::string;

	*cipher="";

	for(int i=0; i<(*sb).size(); i++)
	{
		*cipher += des_sender_64bitBlock((*sb)[i], key);
	}



	return *cipher;
}




int main()
{
	string text;
	cout<<"text : ";
	getline(cin,text);

	cout<<endl;
	string tb = textToBinary(text);
	cout<<"plain text in binary : \n"<<tb<<endl<<endl;

	string bp = bitPadding(tb);
	cout<<"plain text in binary after padding : \n"<<bp<<endl<<endl;


	vector <string> sb = stringSegmentation(bp);

	cout<<"plain text segmented in 64bit blocks:"<<endl;
	for(int i=0; i<sb.size(); i++)
	{
		cout<<sb[i]<<endl;
	}

	cout<<endl;
	string key = keyInput();
	cout<<endl;
	cout<<"key in binary : \n"<<key<<endl<<endl;



	string cipherText = des_encrypt(text,key);

	cout<<"cipher text : \n"<<cipherText<<endl<<endl;

	vector <string> cb = stringSegmentation(cipherText);


	cout<<"cipher text segmented in 64bit blocks:"<<endl;
	for(int i=0; i<cb.size(); i++)
	{
		cout<<cb[i]<<endl;
	}





	return 0;
}

/*
	Hossam ElDin Khaled Mohamed Ali ElShaer
	16P3025
	AES
*/

#include "iostream"

#include <vector>
#include <string>
#include <map>

using namespace std;

string hex_to_bin(string input) {
	map<char, string> map;
	map['0'] = "0000"; map['1'] = "0001"; map['2'] = "0010"; map['3'] = "0011";
	map['4'] = "0100"; map['5'] = "0101"; map['6'] = "0110"; map['7'] = "0111";
	map['8'] = "1000"; map['9'] = "1001"; map['A'] = "1010"; map['B'] = "1011";
	map['C'] = "1100"; map['D'] = "1101"; map['E'] = "1110"; map['F'] = "1111";
	map[' '] = "";

	string mapped_bin = "";
	for (int i = 0; i < input.length(); i++) {
		mapped_bin += map[input[i]];
	}

	return mapped_bin;
}
string bin_to_hex(string input) {
	map<string, char> map;
	map["0000"] = '0'; map["0001"] = '1'; map["0010"] = '2'; map["0011"] = '3';
	map["0100"] = '4'; map["0101"] = '5'; map["0110"] = '6'; map["0111"] = '7';
	map["1000"] = '8'; map["1001"] = '9'; map["1010"] = 'A'; map["1011"] = 'B';
	map["1100"] = 'C'; map["1101"] = 'D'; map["1110"] = 'E'; map["1111"] = 'F';

	string mapped_hex = "";
	for (int i = 0; i < input.length(); i += 4) {
		mapped_hex += map[input.substr(i, 4)];
	}

	return mapped_hex;
}
int bin_to_dec_4bit(string input) {
	map<string, int> map;
	map["0000"] = 0; map["0001"] = 1; map["0010"] = 2; map["0011"] = 3;
	map["0100"] = 4; map["0101"] = 5; map["0110"] = 6; map["0111"] = 7;
	map["1000"] = 8; map["1001"] = 9; map["1010"] = 10; map["1011"] = 11;
	map["1100"] = 12; map["1101"] = 13; map["1110"] = 14; map["1111"] = 15;

	return map[input];
}
int bin_to_dec_8bit(string input) {
	int a = bin_to_dec_4bit(input.substr(0, 4)) << 4;
	int b = bin_to_dec_4bit(input.substr(4, 4));
	return a + b;
}
string dec_to_bin_4bit(int input) {
	string map[16] = { "0000", "0001", "0010", "0011",
						"0100", "0101", "0110", "0111",
						"1000", "1001", "1010", "1011",
						"1100", "1101", "1110", "1111" };

	return map[input];
}
string dec_to_bin_8bit(int input) {
	return dec_to_bin_4bit((input & 0xf0) >> 4) + dec_to_bin_4bit(input & 0x0f);
}

string perform_xor(string s1, string s2) {
	string result = "";
	for (int i = 0; i < s1.length(); i++) {
		result += ((s1[i] - 48) ^ (s2[i] - 48)) + 48;
	}

	return result;
}

string rotate_word(string word) {
	// input 32 bit word
	return word.substr(8, 24) + word.substr(0, 8);
}
string substitute_word(string word) {
	// input 32-bit word
	int sbox[16][16] = {
		   0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
		   0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
		   0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
		   0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
		   0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
		   0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
		   0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
		   0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
		   0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
		   0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
		   0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
		   0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
		   0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
		   0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
		   0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
		   0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
	};

	string substitued = "";
	for (int i = 0; i < 4; i++) {
		int row = bin_to_dec_4bit(word.substr(i * 8, 4));
		int col = bin_to_dec_4bit(word.substr(i * 8 + 4, 4));
		substitued += dec_to_bin_8bit((sbox[row][col]));
	}
	return substitued;
}
string add_round_const(string word, int round) {
	int round_const[10]{
		0x01, 0x02, 0x04, 0x08, 0x10,
		0x20, 0x40, 0x80, 0x1b, 0x36
	};

	string rc = dec_to_bin_8bit(round_const[round]) + "000000000000000000000000";
	return perform_xor(word, rc);
}
vector<string> key_expansion(string key) {
	vector<string> round_keys;

	string round_key = key;
	round_keys.push_back(round_key);
	for (int i = 0; i < 10; i++) {
		string last_word = round_key.substr(96, 32);
		last_word = rotate_word(last_word);
		last_word = substitute_word(last_word);
		last_word = add_round_const(last_word, i);

		string first_word = perform_xor(round_key.substr(0, 32), last_word);
		string second_word = perform_xor(round_key.substr(32, 32), first_word);
		string third_word = perform_xor(round_key.substr(64, 32), second_word);
		string fourth_word = perform_xor(round_key.substr(96, 32), third_word);
		round_key = first_word + second_word + third_word + fourth_word;

		round_keys.push_back(round_key);
	}


	return round_keys;
}

string substitute_byte(string plaintext) {
	return substitute_word(plaintext.substr(0, 32)) +
		substitute_word(plaintext.substr(32, 32)) +
		substitute_word(plaintext.substr(64, 32)) +
		substitute_word(plaintext.substr(96, 32));
}
string shift_rows(string plaintext) {
	string w1 = plaintext.substr(0, 8) + plaintext.substr(32 + 8, 8) + plaintext.substr(64 + 16, 8) + plaintext.substr(96 + 24, 8);
	string w2 = plaintext.substr(32, 8) + plaintext.substr(64 + 8, 8) + plaintext.substr(96 + 16, 8) + plaintext.substr(0 + 24, 8);
	string w3 = plaintext.substr(64, 8) + plaintext.substr(96 + 8, 8) + plaintext.substr(0 + 16, 8) + plaintext.substr(32 + 24, 8);
	string w4 = plaintext.substr(96, 8) + plaintext.substr(0 + 8, 8) + plaintext.substr(32 + 16, 8) + plaintext.substr(64 + 24, 8);
	return w1 + w2 + w3 + w4;
}
string mul_in_gf8(int a, int b) {
	int result = 0;
	for (int i = 0; i < 8; i++) {
		if ((b & 1) != 0)
			result ^= a;

		bool msb = (a & 0x80) != 0;
		a <<= 1;
		if (msb) a ^= 0x1B;
	
		b >>= 1;
	}

	return dec_to_bin_8bit(result);
}
string mix_col(string word) {
	int mix_col[4][4] = { 2, 3, 1, 1,  1, 2, 3, 1,  1, 1, 2, 3,  3, 1, 1, 2 };

	int plain_mat[4];
	for (int j = 0; j < 4; j++)
		plain_mat[j] = bin_to_dec_8bit(word.substr(j * 8, 8));

	string ciphertext = "";
	for (int i = 0; i < 4; i++) {
		string sum = "00000000";
		for (int j = 0; j < 4; j++) {
			string result = mul_in_gf8(mix_col[i][j], plain_mat[j]);
			sum = perform_xor(sum, result);
		}
		ciphertext += sum;
	}
	return ciphertext;
}
string mix_columns(string plaintext) {
	string ciphertext = "";
	for (int i = 0; i < 4; i++)
		ciphertext += mix_col(plaintext.substr(i * 32, 32));

	return ciphertext;
}
string aes_encryption(string plaintext, string key) {
	vector<string> round_keys = key_expansion(key);

	string ciphertext = perform_xor(plaintext, round_keys[0]);
	for (int i = 1; i < 11; i++) {
		ciphertext = substitute_byte(ciphertext);

		ciphertext = shift_rows(ciphertext);

		if(i != 10) ciphertext = mix_columns(ciphertext);

		ciphertext = perform_xor(ciphertext, round_keys[i]);
	}

	return ciphertext;
}

string dec_substitute_word(string word) {
	// input 32-bit word
	int sbox[16][16] = {
		0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
		0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
		0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
		0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
		0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
		0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
		0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
		0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
		0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
		0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
		0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
		0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
		0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
		0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
		0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
		0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
	};

	string substitued = "";
	for (int i = 0; i < 4; i++) {
		int row = bin_to_dec_4bit(word.substr(i * 8, 4));
		int col = bin_to_dec_4bit(word.substr(i * 8 + 4, 4));
		substitued += dec_to_bin_8bit((sbox[row][col]));
	}
	return substitued;
}
string dec_substitute_byte(string plaintext) {
	return dec_substitute_word(plaintext.substr(0, 32)) +
		dec_substitute_word(plaintext.substr(32, 32)) +
		dec_substitute_word(plaintext.substr(64, 32)) +
		dec_substitute_word(plaintext.substr(96, 32));
}
string dec_shift_rows(string ciphertext) {
	string w1 = ciphertext.substr(0, 8) + ciphertext.substr(96 + 8, 8) + ciphertext.substr(64 + 16, 8) + ciphertext.substr(32 + 24, 8);
	string w2 = ciphertext.substr(32, 8) + ciphertext.substr(0 + 8, 8) + ciphertext.substr(96 + 16, 8) + ciphertext.substr(64 + 24, 8);
	string w3 = ciphertext.substr(64, 8) + ciphertext.substr(32 + 8, 8) + ciphertext.substr(0 + 16, 8) + ciphertext.substr(96 + 24, 8);
	string w4 = ciphertext.substr(96, 8) + ciphertext.substr(64 + 8, 8) + ciphertext.substr(32 + 16, 8) + ciphertext.substr(0 + 24, 8);
	return w1 + w2 + w3 + w4;
}
string dec_mix_col(string word) {
	int mix_col[4][4] = { 
		0x0e, 0x0b, 0x0d, 0x09, 
		0x09, 0x0e, 0x0b, 0x0d, 
		0x0d, 0x09, 0x0e, 0x0b,
		0x0b, 0x0d, 0x09, 0x0e, };

	int plain_mat[4];

	for (int j = 0; j < 4; j++)
		plain_mat[j] = bin_to_dec_8bit(word.substr(j * 8, 8));

	string ciphertext = "";
	for (int i = 0; i < 4; i++) {
		string sum = "00000000";
		for (int j = 0; j < 4; j++) {
			string result = mul_in_gf8(mix_col[i][j], plain_mat[j]);
			sum = perform_xor(sum, result);
		}
		ciphertext += sum;
	}
	return ciphertext;
}
string dec_mix_columns(string ciphertext) {
	string plaintext = "";
	for (int i = 0; i < 4; i++)
		plaintext += dec_mix_col(ciphertext.substr(i * 32, 32));

	return plaintext;
}
string aes_decryption(string ciphertext, string key) {
	vector<string> round_keys = key_expansion(key);

	vector<string> steps;

	string plaintext = ciphertext;

	for (int i = 10; i > 0; i--) {
		plaintext = perform_xor(plaintext, round_keys[i]);
		if (i != 10) plaintext = dec_mix_columns(plaintext);
		plaintext = dec_shift_rows(plaintext);
		plaintext = dec_substitute_byte(plaintext);
	}

	plaintext = perform_xor(plaintext, round_keys[0]);

	return plaintext;
}

int main() {

	cout << "Hossam ELShaer" << endl << "16P3025" << endl << "AES" << endl << endl;

	cout << "Enter 128-bit key (in hex uppercase): ";
	string key;
	cin >> key;

	cout << "Enter 128-bit plaintext (in hex uppercase): ";
	string plaintext;
	cin >> plaintext;

	string ciphertext = aes_encryption(hex_to_bin(plaintext), hex_to_bin(key));

	cout << "Ciphertext: " << bin_to_hex(ciphertext) << endl << endl;

	cout << "Program is finished! Close and start again" << endl;
	string wait;
	cin >> wait;

	return 0;
}
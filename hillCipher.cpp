#include <iostream>
#include <vector>
using namespace std;

int mod26(int x)
{
    return x >= 0 ? (x % 26) : 26 - (abs(x) % 26);
}

string encrypt(string txt, int key[3][3], int n)
{

    vector<int> txtInt;
    vector<int> etxtInt;

    if (n == 2)
    {
        if (txt.length() % 2 != 0)
        {
            txt += "a";
        }

        for (int i = 0; i < txt.length(); i++)
        {
            txtInt.push_back(int(txt[i] - 'a'));
        }

        for (int i = 0; i < txtInt.size(); i += 2)
        {
            etxtInt.push_back(key[0][0] * txtInt[i] + key[0][1] * txtInt[i + 1]);
            etxtInt.push_back(key[1][0] * txtInt[i] + key[1][1] * txtInt[i + 1]);
            etxtInt[i] = mod26(etxtInt[i]);
            etxtInt[i + 1] = mod26(etxtInt[i + 1]);
        }
    }else{
        if (txt.length() % 3 != 0)
        {
            while(txt.length() % 3 != 0){
                txt += "a";
            }
        }

        for (int i = 0; i < txt.length(); i++)
        {
            txtInt.push_back(int(txt[i] - 'a'));
        }

        for (int i = 0; i < txtInt.size(); i += 3)
        {
            etxtInt.push_back(key[0][0] * txtInt[i] + key[0][1] * txtInt[i + 1] + key[0][2] * txtInt[i + 2]);
            etxtInt.push_back(key[1][0] * txtInt[i] + key[1][1] * txtInt[i + 1] + key[1][2] * txtInt[i + 2]);
            etxtInt.push_back(key[2][0] * txtInt[i] + key[2][1] * txtInt[i + 1] + key[2][2] * txtInt[i + 2]);
            etxtInt[i] = mod26(etxtInt[i]);
            etxtInt[i + 1] = mod26(etxtInt[i + 1]);
            etxtInt[i + 2] = mod26(etxtInt[i + 2]);
        }
    }

    string etext = "";

    for (int i = 0; i < etxtInt.size(); i++)
    {
        etext += char(etxtInt[i] + 97);
    }

    return etext;
}

int main(void)
{

    string txt;
    cout << "Enter text to be encrypted : ";
    cin >> txt;
    cout << endl;

    int n;
    cout << "enter key order : ";
    cin >> n;

    int key[3][3];

    if (n == 2)
    {
        cout << endl
             << "give 2x2 key" << endl;
        for (int i = 0; i < 2; i++)
        {
            for (int j = 0; j < 2; j++)
            {
                cin >> key[i][j];
            }
        }
    }
    else
    {
        cout << endl
             << "give 3x3 key" << endl;
        for (int i = 0; i < 3; i++)
        {
            for (int j = 0; j < 3; j++)
            {
                cin >> key[i][j];
            }
        }
    }

    string etxt = encrypt(txt, key, n);
    cout << endl;

    cout << "Entered text given :\t" << txt << endl
         << "Encrypted text :\t" << etxt << endl;

    return 0;
}

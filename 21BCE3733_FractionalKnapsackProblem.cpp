#include <iostream>
#include <vector>
#include <unordered_map>
#include<utility>
using namespace std;

class Item {
    public:
    int index; 
    int profit;
    int weight;

    Item(int index){
        this->index = index;
    }

    void input(){
        cout<<endl;

        cout<<"profit : ";
        int p;
        cin>>p;
        profit = p;

        cout<<"weight : ";
        int w;
        cin>>w;
        weight = w;

        cout<<endl;
    }

    double ratio(){
        return ((profit*1.0)/(weight*1.0));
    }
    // Custom hash function for Item
    struct HashFunction {
        size_t operator()(const Item& item) const {
            return std::hash<int>()(item.index);
        }
    };

    // Custom equality operator for Item
    struct Equality {
        bool operator()(const Item& item1, const Item& item2) const {
            return item1.index == item2.index;
        }
    };
};


//insertion sort in descending order
vector <Item> insertion_sort(vector <Item> v)
{
    for (int i = 1; i < v.size(); i++)
    {
        Item key = v[i];
        int j = i - 1;
        while (key.ratio() > v[j].ratio() && j >= 0)
        {
            // For ascending order, change key> arr[j] to key< arr[j].
            v[j + 1] = v[j];
            --j;
        }
        v[j + 1] = key;
    }

    return v;
}






unordered_map <Item, double, Item::HashFunction, Item::Equality> fractionalKnapsack(vector <Item> v, double capacity){

    //initilization
    unordered_map <Item, double, Item::HashFunction, Item::Equality> quantity;
    for(int i=0; i<v.size(); i++){
        quantity[v[i]] = 0;
    }

    double effectiveCapacity = capacity;

    double amount;

    int i;
    for(i=0; i<v.size(); i++){

        if(v[i].weight > effectiveCapacity){
            break;
        }else{
            amount = 1;
            quantity[v[i]]=amount;
            effectiveCapacity -= v[i].weight * amount; 
        }

    }

    if(i < v.size()){
        amount = effectiveCapacity / (v[i].weight * 1.0);
        quantity[v[i]]=amount;
        effectiveCapacity -= v[i].weight * amount;
    }

    return quantity;
}


void printResult(unordered_map <Item, double, Item::HashFunction, Item::Equality> quantity, vector<Item> v){
    cout<<"Item\t:";
    for(int i=0; i<v.size(); i++){
        cout<<"\t\t"<<v[i].index;
    }
    cout<<endl;
    cout<<"Profit\t:";
    for(int i=0; i<v.size(); i++){
        cout<<"\t\t"<<v[i].profit;
    }
    cout<<endl;
    cout<<"Weight\t:";
    for(int i=0; i<v.size(); i++){
        cout<<"\t\t"<<v[i].weight;
    }
    cout<<endl;
    cout<<"Amount\t:";
    for(int i=0; i<v.size(); i++){
        cout<<"\t\t"<<quantity.at(v[i]);
    }
    cout<<endl;
    cout<<endl;
    double sum = 0;
    for(int i=0; i<v.size(); i++){
        sum += v[i].profit * quantity.at(v[i]);
    }
    cout<<"Maximized profit = "<<sum<<endl;
}


int main()
{
    cout<<"Krishnendu Roy - 21BCE3733"<<endl<<"Fractional Knapsack Algorithm code"<<endl<<endl;

    int n;
    cout<<"enter number of items : ";
    cin>>n;
    cout<<endl;


    vector <Item> objectList;

    for(int i=0; i<n; i++){
        objectList.push_back(Item(i));
    }

    for(int i=0; i<objectList.size(); i++){
        cout<<"for item "<<i;
        objectList[i].input();
    }

    double bagCapacity;
    cout<<endl;
    cout<<"Give Knapsack capacity : ";
    cin>>bagCapacity;
    cout<<endl;



    vector <Item> orderedObjectList = insertion_sort(objectList);

    unordered_map <Item, double, Item::HashFunction, Item::Equality> quantity = fractionalKnapsack(orderedObjectList, bagCapacity);

    printResult(quantity, objectList);


    return 0;
}
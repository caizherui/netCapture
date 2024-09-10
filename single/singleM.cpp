#include<iostream>
#include<mutex>
 
using namespace std;
/*单例模式：构造函数私有化，对外提供一个接口*/
 
//线程安全的单例模式
class lhsingleClass {
public:
	
	static lhsingleClass* getinstance()
	{//双重锁模式
		if (instance == nullptr)
		{//先判断是否为空，如果为空则进入，不为空说明已经存在实例，直接返回
            //进入后加锁
			i_mutex.lock();
			if (instance == nullptr)
			{//再判断一次，确保不会因为加锁期间多个线程同时进入
				instance = new lhsingleClass();
			}
			i_mutex.unlock();//解锁
		}
		return instance;
	}
private:
    static lhsingleClass* instance;
	static mutex i_mutex;//锁
	lhsingleClass(){}
    lhsingleClass(const lhsingleClass& sc) {}//拷贝构造函数也需要设置为私有
};
lhsingleClass* lhsingleClass::instance=nullptr;
mutex lhsingleClass::i_mutex;//类外初始化
 
 
int main()
{
	lhsingleClass* lhsinglep5 = lhsingleClass::getinstance();
	lhsingleClass* lhsinglep6 = lhsingleClass::getinstance();
 
	cout << lhsinglep5 << endl;
	cout << lhsinglep6 << endl;
	system("pause");
	return 0;
}
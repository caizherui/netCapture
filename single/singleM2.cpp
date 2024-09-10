#include<iostream>
 
using namespace std;
/*单例模式：构造函数私有化，对外提供一个接口*/
 
//饿汉模式：不管用不用得到，都构造出来。本身就是线程安全的
class ehsingleClass {
public:
	static ehsingleClass* getinstance()
	{
		return instance;
	}
 
private:
    static ehsingleClass* instance;//静态成员变量必须类外初始化，只有一个
	ehsingleClass() {}
};
ehsingleClass* ehsingleClass::instance = new ehsingleClass();
//类外定义，main开始执行前，该对象就存在了
 
int main()
{
	//饿汉模式
	ehsingleClass* ehsinglep3 = ehsingleClass::getinstance();
	ehsingleClass* ehsinglep4 = ehsingleClass::getinstance();
    ehsingleClass newObject = *ehsinglep3;
	//ehsingleClass* ehsinglep5 = ehsingleClass::get();//非静态成员方法必须通过对象调用，不能通过类域访问
 
	cout << ehsinglep3 << endl;
	cout << ehsinglep4 << endl;
    cout << &newObject << endl;
 
	system("pause");
	return 0;
}
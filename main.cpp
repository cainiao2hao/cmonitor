#include <QtGui/QApplication>
#include "mydialog.h"

int main(int argc, char* argv[])
{
    QApplication a(argc, argv);
//    pthread_t id;
//    int ret = pthread_create(&id, NULL, begingrab, NULL);
//    if (ret != 0)
//    {
//        printf("Create pthread error!\n");
//        exit(1);
//    }
//    cout << "chief process running!"<<endl;
    MyDialog dialog;
    dialog.show();
//    
    return a.exec();
}

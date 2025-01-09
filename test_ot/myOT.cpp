// #include "myIKNP.h"
// #include "myROT.h"
// #include "mybaseOT.h"
#include "test.hpp"
#include <cstdio>
#include <emp-tool/utils/group.h>
#include <memory>
using namespace std;
using namespace lpr21::ot;
using namespace emp;

const static int threads = 1;

int main(int argc, char **argv) {
  int length; // make sure all functions work for non-power-of-two lengths
              // if (argc <= 3)
              // 	length = (1<<20) + 101;
              // else
              // 	length = (1<<atoi(argv[3])) + 101;
              // int maxChoice = 4;

  std::shared_ptr<Group> G = make_shared<Group>();
  BaseOTSender *ot_sender = new BaseOTSender(G, 128);
  BaseOTReceiver *ot_receiver = new BaseOTReceiver(G, 128);
  cout << "BaseOT:\t" << test_mybaseOT(ot_sender, ot_receiver, 128) << " us"
       << endl;

  myIKNPSender *iknp_sender = new myIKNPSender(G);
  myIKNPReceiver *iknp_receiver = new myIKNPReceiver(G);
  cout << "IKNP:\t" << test_myIKNP(iknp_sender, iknp_receiver, 1 << 20) << " us"
       << endl;

  myROTSender *rot_sender = new myROTSender(G);
  myROTReceiver *rot_receiver = new myROTReceiver(G);
  cout << "ROT:\t" << test_myROT(rot_sender, rot_receiver, 1000) << " us"
       << endl;

  myNOTSender *not_sender = new myNOTSender(G, 8, 128);
  myNOTReceiver *not_receiver = new myNOTReceiver(G, 8, 128);
  cout << "NOT:\t" << test_myNOT(not_sender, not_receiver, 8, 128) << " us"
       << endl;
}
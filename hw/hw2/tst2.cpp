#include <string>
#include <iostream>
void foo1(int a, int b) {
	for (int i = 0; i < a; i++) {
		for (int j = 0; j < b; j++) {
			;
		}
	}
}
void foo2() {
	for (int i = 0; i < 2; i++) {
		for (int j = 0; j < 500; j++) {
			if (i == 1 && j == 234)
				break;
		}
	}
}
void foo3() {
	for (int j = 0; j < 4; j++) {
		for (int i = 0; i < 1000; i++) {
			;
		}
	}
}

void foo4(int a) {
	for (int i = 0; i < a; i++) {
		for (int j = 0; j < i; j++) {
			std::cout << "i: " << i << ", j: " << j << std::endl;
		}
	}
}
int main(int argc, char* argv[]) {
	int choice = std::stoi(argv[1]);
	if (choice == 1) {
		foo1(std::stoi(argv[2]), std::stoi(argv[3]));
	}
	else if (choice == 2) {
		foo2();
	}
	else if (choice == 3) {
		foo3();
	}
	else if (choice == 4) {
		foo4(std::stoi(argv[2]));
	}
	return 0;
}
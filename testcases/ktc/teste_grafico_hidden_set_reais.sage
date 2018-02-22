from sage.all import *

def main():

	R = PolynomialRing(QQ, 'x')

	f = QQ['x'].random_element(4-1)
	print (f)


main()
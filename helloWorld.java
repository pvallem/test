

public class helloWorld {

	public static void print(String s){
		System.out.println(s);
	}

	public helloWorld(){
		name = new String();
 		this.name="default";
 	}
 
	public helloWorld(String nm){
 		name = new String();
 		this.name=nm;
 	}

	public static void main(String[] args) {
		// TODO Auto-generated method stub
		helloWorld hW = new helloWorld("Hi created a hello world program");
		print(hW.name);

		helloWorld hW1 = new helloWorld();
		print(hW.name);

	}

	private static String name;
}

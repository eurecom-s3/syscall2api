package fr.eurecom.s3.android_src_logger;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Properties;
import java.util.Scanner;
import java.util.Set;

import com.github.javaparser.*;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.visitor.VoidVisitor;

public class App 
{
	protected static String APIPATH = "api_list";
	protected static String targetImport = "";
	protected static String[] importNames = {};
	protected static String targetImportPackage = "";
	protected static Set<String> avoidClass = null;
	public static BooleanWrapper hasModifications = new BooleanWrapper();

	protected static void loadProperties() {
		Properties properties = new Properties();
		InputStream input = null;
		try {
			input = new FileInputStream("config.properties");
			properties.load(input);
		} catch	(IOException exception) {
			System.err.println("Failed to load properties. Using default ones.");
		} finally {
			targetImport = properties.getProperty("targetImport", "android.util.Log");
			importNames = properties.getProperty("importNames", "android.util.Log:android.util.*").split(":");
			targetImportPackage = properties.getProperty("targetImportPackage", "android.util");
			avoidClass = new HashSet<String>(Arrays.asList(properties.getProperty("avoidClass", "android.util.Log").split(":")));
			MethodVisitor.startLogStringFormat = properties.getProperty("startLogStringFormat", "Log.logAPI(\"S %s\");");
			MethodVisitor.endLogStringFormat = properties.getProperty("endLogStringFormat", "Log.logAPI(\"E %s\");");
		}
	}

	protected static Set<String> readApiList(String path) {
		Set<String> ret = new HashSet<String>(34000, (float) 0.7);
		String line = null, method = null, args = null;
		String[] split = null;
		try {
			InputStream in = new FileInputStream(path);
			Scanner scanner = new Scanner(in);
			while(scanner.hasNextLine()) {
				line = scanner.nextLine();
				split = line.split("\\(");
				method = split[0];
				try {
					args = split[1].split("\\)")[0];
				} catch (ArrayIndexOutOfBoundsException e) {
					args = "";
				}
				ret.add(method + "(" + args + ")");
			}
			scanner.close();
		} catch (FileNotFoundException e) {
			System.err.println("api_list not found");
			e.printStackTrace();
		}
		
		System.err.println("Parsed " + ret.size() + " methods");
		return ret;
	}

	protected static String readFile(InputStream in) {
		StringBuilder ret = new StringBuilder("");
		try (Scanner scanner = new Scanner(in)) {
			while(scanner.hasNextLine()) {
				String line = scanner.nextLine();
				ret.append(line + "\n");
			}
	    }
		return ret.toString();
	}

	protected static boolean compilationUnitContainsImport(CompilationUnit cu) {
		if (cu.getPackageDeclaration().get().getNameAsString().equals(targetImportPackage)) {
			return Boolean.TRUE;
		}
		ImportFinder importFinder = new ImportFinder(importNames);

		return Boolean.TRUE.equals(importFinder.visit(cu, null));
	}

    public static void main( String[] args ) throws IOException
    {
       loadProperties();
    	String code = readFile(System.in);
    	Set<String> apis = readApiList(APIPATH);
    	CompilationUnit cu = JavaParser.parse(code);
	VoidVisitor<?> vv = new ClassVisitor(apis, avoidClass, hasModifications);
        VoidVisitor<?> cv = new DocumentationVisitor();

    	vv.visit(cu, null);
    	cv.visit(cu, null);

		if (!compilationUnitContainsImport(cu)) {
			cu.addImport(targetImport);
		}

		System.out.print(hasModifications.get() ? cu : code);
    }
}

class BooleanWrapper {
	private boolean value;
	public BooleanWrapper() {
		value = false;
	}

	public void set() {
		value = true;
	}

	public boolean get() {
		return value;
	}
}

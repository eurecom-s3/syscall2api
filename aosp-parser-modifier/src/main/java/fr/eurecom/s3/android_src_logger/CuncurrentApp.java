package fr.eurecom.s3.android_src_logger;

import java.io.BufferedWriter;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import com.github.javaparser.*;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.visitor.VoidVisitor;

public class CuncurrentApp extends App 
{
	protected static Set<String> apis; 
	public static void main( String[] args ) throws IOException
    {
        loadProperties();
        apis = readApiList(APIPATH);

        ExecutorService threadPoll = Executors.newFixedThreadPool(10);
        for (String arg : args) {
        	MyTask mTask = createTaskForFile(arg);
        	if (mTask != null) {
        		threadPoll.execute(mTask);
        	}
        }
        threadPoll.shutdown();
        try {
        	threadPoll.awaitTermination(Long.MAX_VALUE, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
        	System.err.println("Interrupted before all the tasks could finish");
        	return;
        }
    }

	private static MyTask createTaskForFile(String filePath) {
		FileInputStream fileInputStream = null;
		String code = null;
		try {
			fileInputStream = new FileInputStream(filePath);
			code = readFile(fileInputStream);
			fileInputStream.close();
		} catch (IOException e) {
			System.err.println(filePath + ": file not found or error on close");
			return null;
		}
		return new MyTask(filePath, code);
	}

}

class MyTask extends Thread {
	private String filePath;
	private String code;
	private String parsedCode;
	private BooleanWrapper hasModifications;

	public MyTask(String filePath, String code) {
		this.code = code;
		this.filePath = filePath;
		this.hasModifications = new BooleanWrapper();
	}

	public void setParsedCode(String parsedCode) {
		this.parsedCode = parsedCode;
	}

	public String getParsedCode() {
		return this.parsedCode;
	}

	public String getFilePath() {
		return this.filePath;
	}

	public String getCode() {
		return this.code;
	}

	private void writeBack() {
		try {
			System.err.println("Writing " + filePath);
			FileWriter fileWriter = new FileWriter(filePath, false);
			BufferedWriter bWriter = new BufferedWriter(fileWriter);
			bWriter.write(this.parsedCode);
			bWriter.close();
		} catch (Exception e) {
			System.err.println(filePath + ": file not found or error on close");
		}		 
	}

	@Override
	public void run() {
		CompilationUnit cu = JavaParser.parse(code);
	    VoidVisitor<?> vv = new ClassVisitor(CuncurrentApp.apis, CuncurrentApp.avoidClass, hasModifications);
        VoidVisitor<?> cv = new DocumentationVisitor();

    	vv.visit(cu, null);
    	cv.visit(cu, null);

		if (!CuncurrentApp.compilationUnitContainsImport(cu)) {
			cu.addImport(CuncurrentApp.targetImport);
		}

		if (hasModifications.get()) {
			this.parsedCode = cu.toString();
			this.writeBack();
		}
	}
}
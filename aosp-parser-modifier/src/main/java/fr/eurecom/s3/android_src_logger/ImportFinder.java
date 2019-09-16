package fr.eurecom.s3.android_src_logger;

import com.github.javaparser.ast.ImportDeclaration;
import com.github.javaparser.ast.visitor.GenericVisitorAdapter;

public class ImportFinder extends GenericVisitorAdapter<Boolean, Void> {
	private String[] toFind;
	
	public ImportFinder(String[] toFind) {
		this.toFind = toFind;
	}
	
	@Override
	public Boolean visit(ImportDeclaration n, Void arg) {
		String imported = n.getNameAsString();
		for (String imp : toFind) {
			if (imp.equals(imported)) {
				return true;
			}
		}
		return null;
	}
	
}

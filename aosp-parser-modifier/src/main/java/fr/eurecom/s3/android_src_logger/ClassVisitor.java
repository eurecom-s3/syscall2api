package fr.eurecom.s3.android_src_logger;

import com.github.javaparser.ast.body.ClassOrInterfaceDeclaration;
import com.github.javaparser.ast.visitor.VoidVisitorAdapter;

import java.util.Set;

import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.PackageDeclaration;

public class ClassVisitor extends VoidVisitorAdapter<Void> {
	private Set<String> apis;
	private Set<String> avoid;
	private BooleanWrapper hasModifications;

	public ClassVisitor(Set<String> apis, Set<String> avoid, BooleanWrapper hasModifications) {
		this.apis = apis;
		this.avoid = avoid;
		this.hasModifications = hasModifications;
	}

	private static String getPackageName(final ClassOrInterfaceDeclaration cd) {
		CompilationUnit cu = null;
		PackageDeclaration pack = null;
		
		cu = cd.findCompilationUnit().get();
		pack = cu.getPackageDeclaration().get();
		
		try {
			return pack.getName().asString();
		} catch (Exception e) {
			return "";
		}
	}

	private static String getCanonicalName(final ClassOrInterfaceDeclaration cd) {
		String pack = getPackageName(cd);
		return pack + "." + cd.getNameAsString();
	}
	
	@Override
	public void visit(ClassOrInterfaceDeclaration cd, Void v) {
		String packageName = null;
		String className = null;

		if (getCanonicalName(cd).equals(avoid)) {
			return;
		}

		if (cd.isAbstract()) {
			return;
		}

		try {
			packageName = ClassVisitor.getPackageName(cd);
			className = cd.getName().asString();
		} catch(Exception e) {
			System.err.println("Compilation unit not found");
			return;
		}

		MethodVisitor mv = new MethodVisitor(this.apis, packageName, className, hasModifications);
		mv.visit(cd, null);
		
	}
}

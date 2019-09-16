package fr.eurecom.s3.android_src_logger;

import com.github.javaparser.ast.body.CallableDeclaration;
import com.github.javaparser.ast.body.ConstructorDeclaration;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.stmt.BlockStmt;
import com.github.javaparser.ast.stmt.ExplicitConstructorInvocationStmt;
import com.github.javaparser.ast.stmt.Statement;
import com.github.javaparser.ast.visitor.VoidVisitorAdapter;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import com.github.javaparser.JavaParser;
import com.github.javaparser.ast.Modifier;
import com.github.javaparser.ast.Node;

public class MethodVisitor extends VoidVisitorAdapter<Void> {
	private Set<String> apis;
	private String packageName, className;
	public static String startLogStringFormat = "";
	public static String endLogStringFormat = "";
	private BooleanWrapper hasModifications;

	public MethodVisitor(Set<String> apis, String packageName, String className, BooleanWrapper hasModifications) {
		this.apis = apis;
		this.packageName = packageName;
		this.className = className;
		this.hasModifications = hasModifications;
	}

	@SuppressWarnings("rawtypes")
	private boolean isInteresting(CallableDeclaration cd) {
		return this.apis.contains(this.getCanonicalName(cd));
	}

	private String arguments(CallableDeclaration<?> cd) {
		if (cd instanceof MethodDeclaration)
			return ((MethodDeclaration) cd).getParameters().stream().map(x -> x.getType().asString()).collect(Collectors.joining(", "));
		if (cd instanceof ConstructorDeclaration)
			return ((ConstructorDeclaration) cd).getParameters().stream().map(x -> x.getType().asString()).collect(Collectors.joining(", "));
		return "";
	}

	private String getCanonicalName(CallableDeclaration<?> cd) {
		if (cd instanceof MethodDeclaration) return getMethodCanonicalName((MethodDeclaration) cd);
		if (cd instanceof ConstructorDeclaration) return getConstructorCanonicalName((ConstructorDeclaration) cd);
		return "";
	}

	private String getConstructorCanonicalName(ConstructorDeclaration cd) {
		return this.packageName + "." + this.className + "." + this.className + '(' + arguments(cd) + ')';
	}

	private String getMethodCanonicalName(MethodDeclaration md) {
		String methodName = md.getName().asString();
		return this.packageName + "." + this.className + "." + methodName + '(' + arguments(md) + ')';
	}

	private Statement buildLogStatement(CallableDeclaration<?> cd, boolean start) {
		String log = String.format((start ? startLogStringFormat: endLogStringFormat), this.getCanonicalName(cd));
		Statement stmt = JavaParser.parseStatement(log);
		return stmt;
	}

	private BlockStmt addStartLog(CallableDeclaration<?> cd) throws Exception {
		BlockStmt body;
		Statement startLog = this.buildLogStatement(cd, true);
		if (cd instanceof MethodDeclaration)
			body = ((MethodDeclaration) cd).getBody().get();
		else if (cd instanceof ConstructorDeclaration)
			body = ((ConstructorDeclaration) cd).getBody();
		else
			throw new Exception();

		int stmtEntry = 0;
		if (cd instanceof ConstructorDeclaration &&
				body.getStatement(stmtEntry) instanceof ExplicitConstructorInvocationStmt)
				stmtEntry++;

		if (!body.getStatement(stmtEntry).equals(startLog)) {
			body.addStatement(stmtEntry, startLog);
			hasModifications.set();
		}
		return body;
	}

	private void addLog(CallableDeclaration<?> cd) {
		InvocationCounter cnt = new InvocationCounter();
		BlockStmt body;
		Statement endLog = this.buildLogStatement(cd, false);

		try {
			body = this.addStartLog(cd);

			EncloseEndStatementsWithBlocksVisitor ebv = new EncloseEndStatementsWithBlocksVisitor();
			ebv.visit(cd);

			EndOfFunctionVisitor ev = new EndOfFunctionVisitor(endLog, hasModifications);
			ev.visit(cd, cnt);

			int stmtsCount = body.getStatements().size();

			if ((cd instanceof MethodDeclaration && ((MethodDeclaration) cd).getType().asString().equals("void")) ||
					cd instanceof ConstructorDeclaration) {
				Statement lastStatement = body.getStatement(stmtsCount - 1);
				if (lastStatement.isBlockStmt() && ! lastStatement.getChildNodes().isEmpty()) {
					List<Node> childNodes = lastStatement.getChildNodes();
					lastStatement = (Statement) childNodes.get(childNodes.size() - 1);
				}
				if (! (lastStatement.isReturnStmt()
						|| lastStatement.isThrowStmt()
						|| lastStatement.equals(endLog))) {
					hasModifications.set();
					body.addStatement(endLog);
				}
			}
		} catch (Exception e) {
			return;
		}
	}

	@Override
	public void visit(MethodDeclaration md, Void v) {
		if (!md.getModifiers().contains(Modifier.PUBLIC)) {
			return;
		}
		if (isInteresting(md)) {
			this.addLog(md);
		}
	}

	@Override
	public void visit(ConstructorDeclaration cd, Void arg) {
		if (!cd.getModifiers().contains(Modifier.PUBLIC)) {
			return;
		}
		if (isInteresting(cd)) {
			this.addLog(cd);
		}
	}

}

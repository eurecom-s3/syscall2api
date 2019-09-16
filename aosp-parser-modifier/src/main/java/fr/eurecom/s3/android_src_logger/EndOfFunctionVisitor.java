package fr.eurecom.s3.android_src_logger;

import java.util.Optional;

import com.github.javaparser.ast.Node;
import com.github.javaparser.ast.body.CallableDeclaration;
import com.github.javaparser.ast.body.ConstructorDeclaration;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.body.VariableDeclarator;
import com.github.javaparser.ast.expr.CastExpr;
import com.github.javaparser.ast.expr.Expression;
import com.github.javaparser.ast.expr.NameExpr;
import com.github.javaparser.ast.expr.ObjectCreationExpr;
import com.github.javaparser.ast.expr.VariableDeclarationExpr;
import com.github.javaparser.ast.stmt.BlockStmt;
import com.github.javaparser.ast.stmt.ReturnStmt;
import com.github.javaparser.ast.stmt.Statement;
import com.github.javaparser.ast.stmt.ThrowStmt;
import com.github.javaparser.ast.type.ClassOrInterfaceType;
import com.github.javaparser.ast.type.Type;
import com.github.javaparser.ast.visitor.ModifierVisitor;
import com.github.javaparser.ast.visitor.Visitable;
import com.github.javaparser.utils.Pair;

public class EndOfFunctionVisitor extends ModifierVisitor<InvocationCounter> {
	private Statement toAdd;
	private BooleanWrapper hasModifications;

	public EndOfFunctionVisitor(Statement toAdd, BooleanWrapper hasModifications) {
		super();
		this.toAdd = toAdd;
		this.hasModifications = hasModifications;
	}

	private boolean addStatementBeforeEndOfBlock(BlockStmt blck, Statement endStatement) {
		int stmtsCount = blck.getStatements().size(), i;

		for (i = 0; i < stmtsCount; ++i) {
			if (blck.getStatement(i).equals(endStatement)) {
				break;
			}
		}

		if (i != stmtsCount && //check whether we've found the statement
				(i == 0 // if the statement is the first (and the only, according to the java language) statement in the block
				||
				i > 0 && ! blck.getStatement(i - 1).equals(toAdd)) // or if it's not the first and it does not follow an API log call
			) {
			// Add the API log statement
			blck.addStatement(i, toAdd);
			hasModifications.set();
			return true;
		}

		return false;
	}

	private Visitable commonVisit(Statement stmt, InvocationCounter cnt) {
		@SuppressWarnings("rawtypes")
		Optional parent = stmt.getAncestorOfType(BlockStmt.class);
		if (!parent.isPresent()) {
			BlockStmt blockStmt = new BlockStmt();
			blockStmt.addAndGetStatement(stmt);
			addStatementBeforeEndOfBlock(blockStmt, stmt);
			return blockStmt;
		}

		if (! this.addStatementBeforeEndOfBlock(stmt.getAncestorOfType(BlockStmt.class).get(), stmt)) {
			BlockStmt retBlock = new BlockStmt();
			retBlock.addAndGetStatement(this.toAdd);
			Statement newRet = stmt.clone();
			retBlock.addAndGetStatement(stmt);
			stmt.getParentNode().get().replace(stmt, retBlock);
			stmt = newRet;
		}

		cnt.count();
		return stmt;
	}

	private Type getTypeFromMethodDeclaration(java.util.Optional<MethodDeclaration> optional) {
		if (! optional.isPresent()) {
			System.err.println("Something went terribly wrong. Return statement does not have any MethodDeclaration ancestors");
			return null;
		}
		MethodDeclaration methodDeclaration = optional.get();
		return methodDeclaration.getType();
	}

	private Type getTypeFromThrowException(Node expr) throws Exception
	{
		if (expr instanceof ObjectCreationExpr) {
			return ((ObjectCreationExpr)expr).getType();
		}
		if (expr instanceof CastExpr) {
			return ((CastExpr) expr).getType();
		}
		throw new Exception(expr.toString() + " is not either an ObjectCreationExpr now a CastExpr. It's a " + expr.getClass());
	}

	private Pair<BlockStmt, Statement> splitStatement(Statement stmt, Boolean exceptionReturnType) throws Exception {
		BlockStmt ret = new BlockStmt();
		VariableDeclarationExpr decl = new VariableDeclarationExpr();
		VariableDeclarator declarator = new VariableDeclarator();
		declarator.setName("this_should_not_break_stuff");

		Type declarationType;
		declarationType = exceptionReturnType ?
				getTypeFromThrowException(stmt.getChildNodes().get(0)):
				getTypeFromMethodDeclaration(stmt.getAncestorOfType(MethodDeclaration.class));
		declarator.setType(declarationType);
		declarator.setInitializer((Expression) stmt.getChildNodes().get(0));
		decl.addVariable(declarator);
		ret.addStatement(decl);

		Statement newEndStmt = null;
		NameExpr nameExpr = new NameExpr();
		nameExpr.setName("this_should_not_break_stuff");
		if(stmt instanceof ReturnStmt) {
			newEndStmt = new ReturnStmt();
			((ReturnStmt) newEndStmt).setExpression(nameExpr);
		} else if(stmt instanceof ThrowStmt) {
			newEndStmt = new ThrowStmt();
			((ThrowStmt) newEndStmt).setExpression(nameExpr);
		}
		ret.addStatement(newEndStmt);

		return new Pair<BlockStmt, Statement>(ret, newEndStmt);
	}

	private Statement replaceEndWithBlock(Statement returnStmt, Boolean exceptionReturnType) throws Exception {
		Pair<BlockStmt, Statement> newBlock = splitStatement(returnStmt, exceptionReturnType);
		Node parent = returnStmt.getParentNode().get();
		parent.replace(returnStmt, newBlock.a);
		return newBlock.b;
	}

	@Override
	public Visitable visit(ReturnStmt stmt, InvocationCounter cnt) {
		if (! stmt.getChildNodes().isEmpty() ) {
			if (! (stmt.getChildNodes().get(0) instanceof NameExpr)
					&& stmt.getParentNode().isPresent()) {
				try {
					return commonVisit(replaceEndWithBlock(stmt, false), cnt);
				} catch (Exception e) {
					return commonVisit(stmt, cnt);
				}
			}
		}
		return commonVisit(stmt, cnt);
	}

	@Override
	public Visitable visit(ThrowStmt stmt, InvocationCounter cnt) {
		if (! stmt.getChildNodes().isEmpty() ) {
			if (! (stmt.getChildNodes().get(0) instanceof NameExpr)
					&& stmt.getParentNode().isPresent()) {
				ClassOrInterfaceType cInterfaceType = new ClassOrInterfaceType();
				cInterfaceType.setName("Throwable");
				try {
					return commonVisit(replaceEndWithBlock(stmt, true), cnt);
				} catch (Exception e) {
					return commonVisit(stmt, cnt);
				}
			}
		}
		return commonVisit(stmt, cnt);
	}

	public Visitable visit(CallableDeclaration<?> cd, InvocationCounter cnt) {
		if (cd instanceof MethodDeclaration)
			return super.visit((MethodDeclaration) cd, cnt);
		if (cd instanceof ConstructorDeclaration)
			return super.visit((ConstructorDeclaration) cd, cnt);
		return null;
	}
}

class InvocationCounter {
	private int counter;
	public InvocationCounter() {
		this.counter = 0;
	}

	public InvocationCounter(int cnt) {
		this.counter = cnt;
	}

	public void count() {
		this.counter++;
	}

	public int get() {
		return counter;
	}

	@Override
	public String toString() {
		Integer i = counter;
		return i.toString();
	}
}
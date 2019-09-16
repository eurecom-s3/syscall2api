package fr.eurecom.s3.android_src_logger;

import com.github.javaparser.ast.Node;
import com.github.javaparser.ast.body.CallableDeclaration;
import com.github.javaparser.ast.body.ConstructorDeclaration;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.stmt.BlockStmt;
import com.github.javaparser.ast.stmt.ReturnStmt;
import com.github.javaparser.ast.stmt.Statement;
import com.github.javaparser.ast.stmt.ThrowStmt;
import com.github.javaparser.ast.visitor.ModifierVisitor;
import com.github.javaparser.ast.visitor.Visitable;

public class EncloseEndStatementsWithBlocksVisitor extends ModifierVisitor<Void>{
	private Statement encloseWithBlock(Statement stmt) {
		Node parent = stmt.getParentNode().get();
		BlockStmt blockStmt = new BlockStmt();
		blockStmt.addAndGetStatement(stmt.clone());
		parent.replace(stmt, blockStmt);
		return blockStmt;
	}

	public Visitable visit(ReturnStmt returnStmt, Void v) {
		@SuppressWarnings("unused")
		BlockStmt parent;
		try {
			parent = (BlockStmt) returnStmt.getParentNode().get();
		} catch (Exception e) {
			return encloseWithBlock(returnStmt);
		}
		return returnStmt;
	}

	public Visitable visit(ThrowStmt returnStmt, Void v) {
		@SuppressWarnings("unused")
		BlockStmt parent;
		try {
			parent = (BlockStmt) returnStmt.getParentNode().get();
		} catch (Exception e) {
			return encloseWithBlock(returnStmt);
		}
		return returnStmt;
	}

	public Visitable visit(CallableDeclaration<?> cd) {
		if (cd instanceof MethodDeclaration)
			return this.visit((MethodDeclaration) cd, null);
		if (cd instanceof ConstructorDeclaration)
			return this.visit((ConstructorDeclaration) cd, null);
		return null;
	}
}

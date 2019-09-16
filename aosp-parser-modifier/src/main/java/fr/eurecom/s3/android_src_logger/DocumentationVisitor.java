package fr.eurecom.s3.android_src_logger;

import com.github.javaparser.ast.comments.JavadocComment;
import com.github.javaparser.ast.visitor.VoidVisitorAdapter;

public class DocumentationVisitor extends VoidVisitorAdapter<Void> {

	@Override
	public void visit(JavadocComment n, Void arg) {
		String content = n.getContent();
		if(content.contains("@code")) {
			if (content.contains("@hide")) {
				n.setContent("@hide");
			} else {
				n.setContent("");
			}
			// Voluntarily avoid to set hasModifications: we don't want to rewrite the file for just modifications in the comments
		}
	}

}

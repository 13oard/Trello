package com.sparta.trello.domain.card.repository;

import com.querydsl.jpa.impl.JPAQueryFactory;
import com.sparta.trello.domain.comment.entity.Comment;
import com.sparta.trello.domain.comment.entity.CommentStatus;
import com.sparta.trello.domain.comment.entity.QComment;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.Pageable;

import java.util.List;

@RequiredArgsConstructor
public class CardRepositoryImpl implements CardRepositoryCustom {

    private final JPAQueryFactory queryFactory;

    @Override
    public Page<Comment> findCommentsByCardId(Long cardId, Pageable pageable) {
        QComment qComment = QComment.comment;

        List<Comment> comments = queryFactory.selectFrom(qComment)
                .where(qComment.card.id.eq(cardId).and(qComment.status.eq(CommentStatus.ACTIVE)))
                .orderBy(qComment.createAt.desc())
                .offset(pageable.getOffset())
                .limit(pageable.getPageSize())
                .fetch();

        long total = queryFactory.selectFrom(qComment)
                .where(qComment.card.id.eq(cardId).and(qComment.status.eq(CommentStatus.ACTIVE)))
                .fetchCount();

        return new PageImpl<>(comments, pageable, total);
    }
}
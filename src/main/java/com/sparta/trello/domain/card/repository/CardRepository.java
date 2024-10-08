package com.sparta.trello.domain.card.repository;

import com.sparta.trello.domain.card.entity.Card;
import org.springframework.data.jpa.repository.JpaRepository;

public interface CardRepository extends JpaRepository<Card, Long>, CardRepositoryCustom {

}

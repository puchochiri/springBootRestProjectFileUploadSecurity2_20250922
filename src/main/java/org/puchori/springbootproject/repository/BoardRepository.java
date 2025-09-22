package org.puchori.springbootproject.repository;

import org.puchori.springbootproject.domain.Board;
import org.puchori.springbootproject.repository.search.BoardSearch;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.Optional;

public interface BoardRepository extends JpaRepository<Board, Long>, BoardSearch {




  @Query(value = "select now()", nativeQuery = true)
  String getTime();


  Page<Board> searchAll(String[] types, String keyword, Pageable pageable);

  @EntityGraph(attributePaths = {"imageSet"})
  @Query("select b from Board b where b.bno =:bno")
  Optional<Board> findbyIdWithImages(Long bno);
}


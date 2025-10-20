package org.puchori.springbootproject.service;

import org.puchori.springbootproject.dto.MemberJoinDTO;

public interface MemberService {

    static class MidExistException extends Exception {

    }

    void join(MemberJoinDTO memberJoinDTO) throws MidExistException;
}

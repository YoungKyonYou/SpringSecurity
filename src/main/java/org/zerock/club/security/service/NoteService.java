package org.zerock.club.security.service;

import org.zerock.club.entity.ClubMember;
import org.zerock.club.entity.Note;
import org.zerock.club.security.dto.NoteDTO;

import java.util.List;

public interface NoteService {
    Long register(NoteDTO noteDTO);
    NoteDTO get(Long num);
    void modify(NoteDTO noteDTO);
    List<NoteDTO> getAllWithWriter(String writerEmail);

    void remove(Long num);

    default Note dtoToEntity(NoteDTO noteDTO){
        Note note = Note.builder()
                .num(noteDTO.getNum())
                .title(noteDTO.getTitle())
                .content(noteDTO.getContent())
                .writer(ClubMember.builder().email(noteDTO.getWriterEmail()).build())
                .build();
        return note;
    }

    default NoteDTO entityToDTO(Note note){
        NoteDTO noteDTO = NoteDTO.builder()
                .num(note.getNum())
                .content(note.getContent())
                .title(note.getTitle())
                .content(note.getContent())
                .writerEmail(note.getWriter().getEmail())
                .build();
        return noteDTO;
    }
}

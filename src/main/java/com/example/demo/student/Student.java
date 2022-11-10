package com.example.demo.student;

import lombok.Data;

@Data
//A shortcut for @ToString, @EqualsAndHashCode, @Getter on all fields, and @Setter on all non-final fields,
// and @RequiredArgsConstructor!
public class Student {
    private final Integer studentId;
    private final String studentName;

    public Student(Integer studentId, String studentName) {
        this.studentId = studentId;
        this.studentName = studentName;
    }
}

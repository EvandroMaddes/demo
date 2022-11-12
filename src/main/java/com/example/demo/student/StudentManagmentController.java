package com.example.demo.student;

import org.springframework.web.bind.annotation.*;

import java.util.Arrays;
import java.util.List;

@RestController
@RequestMapping("management/api/v1/students")
public class StudentManagmentController {
    private final List<Student> STUDENT = Arrays.asList(
            new Student(1, "Evandro"),
            new Student(2, "Angela"),
            new Student(3, "Emanuele")
    );

    @GetMapping
    public List<Student> getAllStudents() {
        return STUDENT;
    }

    @PostMapping
    public void registerNewStudent(@RequestBody Student student) {
        System.out.println("New student " + student.getStudentName() + " registered");
    }

    @DeleteMapping(path = "{studentId}")
    public void deleteStudent(@PathVariable("studentId") Integer studentId) {
        System.out.println("Student " + STUDENT.get(studentId) + " deleted");
    }

    @PutMapping(path = "{studentId}")
    public void updateStudent(@PathVariable("studentId") Integer studentId, @RequestBody Student student) {
        System.out.println("Student " + STUDENT.get(studentId) + " updated to student " + student);
    }
}

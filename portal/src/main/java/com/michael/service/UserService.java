package com.michael.service;

import com.michael.domain.User;
import com.michael.exceptions.domain.EmailExistException;
import com.michael.exceptions.domain.UserNotFoundException;
import com.michael.exceptions.domain.UsernameExistException;
import org.springframework.web.multipart.MultipartFile;

import javax.mail.MessagingException;
import java.io.IOException;
import java.util.List;

public interface UserService {

    User register(String firstName, String lastName, String username, String email) throws UserNotFoundException, EmailExistException, UsernameExistException, MessagingException;

    List<User> getUsers();

    User findUserByUsername(String username);

    User findUserByEmail(String email);

    User addNewUser(String firstName, String lastName,
                    String username,
                    String email, String role,
                    boolean isNonLocked, boolean isActive,
                    MultipartFile profileImage) throws UserNotFoundException, EmailExistException, UsernameExistException, IOException;

    User updateUser(String currentUserName,
                    String newFirstName,
                    String newUsername,
                    String newLastName,
                    String newEmail, String role,
                    boolean isNonLocked, boolean isActive,
                    MultipartFile profileImage) throws UserNotFoundException, EmailExistException, UsernameExistException, IOException;

    void deleteId(long id);

    void resetPassword(String email) throws EmailExistException, MessagingException;

    User updateProfileImage(String username, MultipartFile profileImage) throws UserNotFoundException, EmailExistException, UsernameExistException, IOException;
}

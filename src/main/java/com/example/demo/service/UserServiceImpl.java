package com.example.demo.service;

import com.example.demo.dto.UserDto;
import com.example.demo.mapper.RoleMapper;
import com.example.demo.mapper.UserMapper;
import com.example.demo.model.RegistrationRequest;
import com.example.demo.model.User;
import com.example.demo.repository.RoleRepository;
import com.example.demo.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService{

    private final UserRepository userRepository;

    private final UserMapper userMapper;

    private final BCryptPasswordEncoder passwordEncoder;

    private final RoleRepository roleRepository;

    private final RoleMapper roleMapper;

    @Override
    public boolean checkEmail(String email) {
        return userRepository.existsByEmailAddress(email);
    }

    @Override
    public UserDto registerUser(RegistrationRequest registrationRequest) {
       User user = User.builder()
               .username(registrationRequest.getUsername())
               .firstName(registrationRequest.getFirstName())
               .lastName(registrationRequest.getLastName())
               .password(registrationRequest.getPassword())
               .emailAddress(registrationRequest.getEmailAddress())
               .role(roleRepository.findByRole("USER"))
               .build();
       return this.createUser(user);
    }

    @Override
    public UserDto getLoginUser() {
        return userMapper.userEntityToDto(userRepository.findLoginUser().orElse(null));
    }

    @Override
    public UserDto getUserById(Integer id) {
        return userMapper.userEntityToDto(userRepository.findById(id).orElse(null));
    }

    @Override
    public List<UserDto> getAllUsers() {
        return userMapper.userListEntityToDto(userRepository.findAll());
    }

    @Override
    public UserDto createUser(User user) {
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        return userMapper.userEntityToDto(userRepository.save(user));
    }

    @Override
    public UserDto updateUser(User user) {
        return userMapper.userEntityToDto(userRepository.save(user));
    }

    @Override
    public void deleteUser(User user) {
        userRepository.delete(user);
    }
}

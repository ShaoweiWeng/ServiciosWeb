/**
 * ETSIINFLibrarySkeleton.java
 *
 * This file was auto-generated from WSDL
 * by the Apache Axis2 version: 1.6.2  Built on : Apr 17, 2012 (05:33:49 IST)
 */
package es.upm.etsiinf.sos;

import java.rmi.RemoteException;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.List;
import java.util.ArrayList;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Logger;

import es.upm.etsiinf.sos.model.xsd.Response;
import es.upm.etsiinf.sos.model.xsd.User;
import es.upm.etsiinf.sos.model.xsd.Book;
import es.upm.etsiinf.sos.model.xsd.MyUser;
import es.upm.fi.sos.t3.backend.UPMAuthenticationAuthorizationWSSkeletonStub;

/**
 * ETSIINFLibrarySkeleton java skeleton for the axisService
 */
public class ETSIINFLibrarySkeleton {
    private UPMAuthenticationAuthorizationWSSkeletonStub serviceStub;

    private static final MyUser ADMIN = new MyUser("admin", "admin");
    private MyUser userSession;

    private static final Map<String, MyUser> registeredUsers = new HashMap<>();
    private static final Map<String, Set<String>> activeUserSessions = new ConcurrentHashMap<>();

    private static final Logger logger = Logger.getLogger(ETSIINFLibrarySkeleton.class.getName());

    private static final List<Book> books = new ArrayList<>();
    private static final Map<String, Integer> ejemplares = new HashMap<>();
    private Map<User, List<Book>> prestamos = new HashMap<>();

    private String generateSessionId() {
        return UUID.randomUUID().toString();
    }

    private boolean isUserAlreadyLoggedIn(String loginUserName) {
        return activeUserSessions.containsKey(loginUserName);
    }

    private boolean isAdmin(String loginUserName, String loginUserPwd) {
        return ADMIN.getUserName().equals(loginUserName) && ADMIN.getPassword().equals(loginUserPwd);
    }

    /**
     * Auto generated method signature
     * 
     * @param borrowBook
     * @return borrowBookResponse
     */

    public es.upm.etsiinf.sos.BorrowBookResponse borrowBook(
            es.upm.etsiinf.sos.BorrowBook borrowBook) {
        // TODO : fill this with the necessary business logic
        throw new java.lang.UnsupportedOperationException(
                "Please implement " + this.getClass().getName() + "#borrowBook");
    }

    /**
     * Auto generated method signature
     * 
     * @param returnBook
     * @return returnBookResponse
     */

    public es.upm.etsiinf.sos.ReturnBookResponse returnBook(
            es.upm.etsiinf.sos.ReturnBook returnBook) {
        // TODO : fill this with the necessary business logic
        throw new java.lang.UnsupportedOperationException(
                "Please implement " + this.getClass().getName() + "#returnBook");
    }

    /**
     * Auto generated method signature
     * 
     * @param logout
     * @return logoutResponse
     */

    public es.upm.etsiinf.sos.LogoutResponse logout(
            es.upm.etsiinf.sos.Logout logout) {
        // TODO : fill this with the necessary business logic
        throw new java.lang.UnsupportedOperationException("Please implement " + this.getClass().getName() + "#logout");
    }

    /**
     * Auto generated method signature
     * 
     * @param removeBook
     * @return removeBookResponse
     */

    public es.upm.etsiinf.sos.RemoveBookResponse removeBook(
            es.upm.etsiinf.sos.RemoveBook removeBook) {
        es.upm.etsiinf.sos.RemoveBookResponse response = new es.upm.etsiinf.sos.RemoveBookResponse();
        es.upm.etsiinf.sos.model.xsd.Response responseAttr = new es.upm.etsiinf.sos.model.xsd.Response();
        responseAttr.setResponse(false);

        // Solo admin puede eliminar libros
        if (userSession == null || !userSession.equals(ADMIN)) {
            logger.info("Acceso denegado: solo el usuario admin puede eliminar libros");
            response.set_return(responseAttr);
            return response;
        }

        String issn = removeBook.getArgs0();
        if (issn == null || issn.trim().isEmpty()) {
            logger.info("ISSN inválido");
            response.set_return(responseAttr);
            return response;
        }

        synchronized (books) {
            for (int i = 0; i < books.size(); i++) {
                Book book = books.get(i);
                if (issn.equals(book.getISSN())) {
                    boolean prestado = false;
                    for (List<Book> librosPrestados : prestamos.values()) {
                        if (librosPrestados != null && librosPrestados.contains(book)) {
                            prestado = true;
                            break;
                        }
                    }
                    if (prestado) {
                        logger.info("No se puede eliminar el libro: está prestado");
                        response.set_return(responseAttr);
                        return response;
                    }
                    int numEjemplares = ejemplares.getOrDefault(issn, 0);
                    if (numEjemplares > 1) {
                        ejemplares.put(issn, numEjemplares - 1);
                        logger.info("Ejemplar eliminado, quedan " + (numEjemplares - 1) + " ejemplares de ISSN: " + issn);
                    } else {
                        ejemplares.remove(issn);
                        books.remove(i);
                        logger.info("Último ejemplar eliminado, libro borrado de la biblioteca: ISSN " + issn);
                    }
                    responseAttr.setResponse(true);
                    response.set_return(responseAttr);
                    return response;
                }
            }
        }
        logger.info("No se encontró ejemplar con ISSN: " + issn + " o está prestado");
        response.set_return(responseAttr);
        return response;
    }

    /**
     * Auto generated method signature
     * 
     * @param deleteUser
     * @return deleteUserResponse
     */

    public es.upm.etsiinf.sos.DeleteUserResponse deleteUser(
            es.upm.etsiinf.sos.DeleteUser deleteUser) {
        // TODO : fill this with the necessary business logic
        throw new java.lang.UnsupportedOperationException(
                "Please implement " + this.getClass().getName() + "#deleteUser");
    }

    /**
     * Auto generated method signature
     * 
     * @param addUser
     * @return addUserResponse
     */

    public es.upm.etsiinf.sos.AddUserResponse addUser(es.upm.etsiinf.sos.AddUser newUser) {
        String newUser_Name = newUser.getArgs0().getUsername();
        logger.info("Attempting to add user: " + newUser_Name);

        AddUserResponse response = new AddUserResponse();
        es.upm.etsiinf.sos.model.xsd.AddUserResponse responseAttr = new es.upm.etsiinf.sos.model.xsd.AddUserResponse();
        responseAttr.setResponse(false);

        if (!userSession.equals(ADMIN)) {
            logger.info("Access denied: Only admin can add users");
        } else {
            try {
                UPMAuthenticationAuthorizationWSSkeletonStub.UserBackEnd userBackEnd = new UPMAuthenticationAuthorizationWSSkeletonStub.UserBackEnd();
                userBackEnd.setName(newUser_Name);

                UPMAuthenticationAuthorizationWSSkeletonStub.AddUser addUserRequest = new UPMAuthenticationAuthorizationWSSkeletonStub.AddUser();
                addUserRequest.setUser(userBackEnd);

                UPMAuthenticationAuthorizationWSSkeletonStub.AddUserResponse serviceResponse = serviceStub
                        .addUser(addUserRequest);

                UPMAuthenticationAuthorizationWSSkeletonStub.AddUserResponseBackEnd backendResponse = serviceResponse
                        .get_return();
                responseAttr.setResponse(backendResponse.getResult());

                if (backendResponse.getResult()) {
                    responseAttr.setPwd(backendResponse.getPassword());
                    registeredUsers.put(newUser_Name, new MyUser(newUser_Name, backendResponse.getPassword()));
                    logger.info("User added successfully: " + newUser_Name);
                } else {
                    logger.info("Failed to add user: " + newUser_Name);
                }
            } catch (RemoteException e) {
                logger.info(e.getMessage());
            }
        }
        response.set_return(responseAttr);
        return response;
    }

    /**
     * Auto generated method signature
     * 
     * @param getBook
     * @return getBookResponse
     */

    public es.upm.etsiinf.sos.GetBookResponse getBook(
            es.upm.etsiinf.sos.GetBook getBook) {
        es.upm.etsiinf.sos.GetBookResponse response = new es.upm.etsiinf.sos.GetBookResponse();
        es.upm.etsiinf.sos.model.xsd.Book bookResult = new es.upm.etsiinf.sos.model.xsd.Book();

        // Verificar que hay un usuario autenticado
        if (userSession == null) {
            logger.info("No hay usuario autenticado para getBook");
            response.set_return(bookResult); // Devuelve objeto vacío
            return response;
        }

        String issn = getBook.getArgs0();
        if (issn == null || issn.trim().isEmpty()) {
            logger.info("ISSN no proporcionado o vacío en getBook");
            response.set_return(bookResult); // Devuelve objeto vacío
            return response;
        }

        // Buscar el libro por ISSN
        synchronized (books) {
            for (Book b : books) {
                if (issn.equals(b.getISSN())) {
                    response.set_return(b);
                    return response;
                }
            }
        }
        // Si no se encuentra, devuelve objeto vacío
        logger.info("No se encontró libro con ISSN: " + issn);
        response.set_return(bookResult);
        return response;
    }

    /**
     * Auto generated method signature
     * 
     * @param listBooks
     * @return listBooksResponse
     */

    public es.upm.etsiinf.sos.ListBooksResponse listBooks(
            es.upm.etsiinf.sos.ListBooks listBooks) {
        es.upm.etsiinf.sos.ListBooksResponse response = new es.upm.etsiinf.sos.ListBooksResponse();
        es.upm.etsiinf.sos.model.xsd.BookList bookList = new es.upm.etsiinf.sos.model.xsd.BookList();

        if (userSession == null) {
            bookList.setResult(false);
            bookList.setBookNames(new String[0]);
            bookList.setIssns(new String[0]);
            response.set_return(bookList);
            logger.info("listBooks: usuario no autenticado");
            return response;
        }

        bookList.setResult(true);
        int n = books.size();
        String[] bookNames = new String[n];
        String[] issns = new String[n];

        for (int i = 0; i < n; i++) {
            Book b = books.get(n - 1 - i);
            bookNames[i] = b.getName();
            issns[i] = b.getISSN();
        }
        
        bookList.setBookNames(bookNames);
        bookList.setIssns(issns);
        response.set_return(bookList);
        logger.info("listBooks: devueltos " + n + " libros");
        return response;
    }

    /**
     * Auto generated method signature
     * 
     * @param changePassword
     * @return changePasswordResponse
     */

    public es.upm.etsiinf.sos.ChangePasswordResponse changePassword(
            es.upm.etsiinf.sos.ChangePassword changePassword) {
        // TODO : fill this with the necessary business logic
        throw new java.lang.UnsupportedOperationException(
                "Please implement " + this.getClass().getName() + "#changePassword");
    }

    /**
     * Auto generated method signature
     * 
     * @param login
     * @return loginResponse
     */

    public es.upm.etsiinf.sos.LoginResponse login(es.upm.etsiinf.sos.Login login) {
        String loginUserName = login.getArgs0().getName();
        String loginUserPwd = login.getArgs0().getPwd();
        logger.info("Attempting login for user: " + loginUserName);

        LoginResponse response = new LoginResponse();
        Response responseAttr = new Response();
        responseAttr.setResponse(false);

        // Case 1: User is already logged in
        if (isUserAlreadyLoggedIn(loginUserName)) {
            responseAttr.setResponse(true);
            logger.info("User: " + loginUserName + " is already logged in");
            // Case 2: User is admin
        } else if (isAdmin(loginUserName, loginUserPwd)) {
            String sessionId = generateSessionId();
            activeUserSessions.computeIfAbsent(loginUserName, k -> ConcurrentHashMap.newKeySet()).add(sessionId);
            responseAttr.setResponse(true);
            logger.info("Admin logged in successfully. Session ID: {}" + sessionId);
            // Case 3: User is registered and not logged in
        } else {
            try {
                UPMAuthenticationAuthorizationWSSkeletonStub.LoginBackEnd loginBackEnd = new UPMAuthenticationAuthorizationWSSkeletonStub.LoginBackEnd();
                loginBackEnd.setName(loginUserName);
                loginBackEnd.setPassword(loginUserPwd);

                UPMAuthenticationAuthorizationWSSkeletonStub.Login loginRequest = new UPMAuthenticationAuthorizationWSSkeletonStub.Login();
                loginRequest.setLogin(loginBackEnd);

                UPMAuthenticationAuthorizationWSSkeletonStub.LoginResponse serviceResponse = serviceStub
                        .login(loginRequest);

                UPMAuthenticationAuthorizationWSSkeletonStub.LoginResponseBackEnd backendResponse = serviceResponse
                        .get_return();

                if (backendResponse.getResult()) {
                    String sessionId = generateSessionId();
                    activeUserSessions.computeIfAbsent(loginUserName, k -> ConcurrentHashMap.newKeySet())
                            .add(sessionId);
                    responseAttr.setResponse(backendResponse.getResult());
                    logger.info("User: " + loginUserName + " logged in successfully. New session ID: " + sessionId);
                } else {
                    logger.info("External authentication failed for user: " + loginUserName);
                }
            } catch (RemoteException e) {
                logger.info(e.getMessage());
            }
        }
        response.set_return(responseAttr);
        return response;
    }

    /**
     * Auto generated method signature
     * 
     * @param addBook
     * @return addBookResponse
     */

    public es.upm.etsiinf.sos.AddBookResponse addBook(
            es.upm.etsiinf.sos.AddBook addBook) {
        es.upm.etsiinf.sos.AddBookResponse response = new es.upm.etsiinf.sos.AddBookResponse();
        es.upm.etsiinf.sos.model.xsd.Response responseAttr = new es.upm.etsiinf.sos.model.xsd.Response();
        responseAttr.setResponse(false);

        if (userSession == null || !userSession.equals(ADMIN)) {
            logger.info("Acceso denegado: solo el usuario admin puede añadir libros");
            response.set_return(responseAttr);
            return response;
        }

        Book book = addBook.getArgs0();
        if (book == null) {
            logger.info("Libro nulo");
            response.set_return(responseAttr);
            return response;
        }

        String name = book.getName();
        String issn = book.getISSN();
        String[] authors = book.getAuthors();

        boolean valid = name != null && !name.trim().isEmpty()
                && issn != null && !issn.trim().isEmpty()
                && authors != null && authors.length > 0;
        if (!valid) {
            logger.info("Libro inválido: faltan campos obligatorios");
            response.set_return(responseAttr);
            return response;
        }

        synchronized (books) {
            boolean existe = false;
            for (Book b : books) {
                if (issn.equals(b.getISSN())) {
                    existe = true;
                    break;
                }
            }
            if (existe) {
                ejemplares.put(issn, ejemplares.get(issn) + 1);
                logger.info("Ejemplar añadido a libro existente: " + name + " (ISSN: " + issn + ")");
            } else {
                books.add(book);
                ejemplares.put(issn, 1);
                logger.info("Libro añadido correctamente: " + name + " (ISSN: " + issn + ")");
            }
        }
        responseAttr.setResponse(true);
        response.set_return(responseAttr);
        return response;
    }

    /**
     * Auto generated method signature
     * 
     * @param getBooksFromAuthor
     * @return getBooksFromAuthorResponse
     */

    public es.upm.etsiinf.sos.GetBooksFromAuthorResponse getBooksFromAuthor(
            es.upm.etsiinf.sos.GetBooksFromAuthor getBooksFromAuthor) {
        // TODO : fill this with the necessary business logic
        throw new java.lang.UnsupportedOperationException(
                "Please implement " + this.getClass().getName() + "#getBooksFromAuthor");
    }

    /**
     * Auto generated method signature
     * 
     * @param listBorrowedBooks
     * @return listBorrowedBooksResponse
     */

    public es.upm.etsiinf.sos.ListBorrowedBooksResponse listBorrowedBooks(
            es.upm.etsiinf.sos.ListBorrowedBooks listBorrowedBooks) {
        // TODO : fill this with the necessary business logic
        throw new java.lang.UnsupportedOperationException(
                "Please implement " + this.getClass().getName() + "#listBorrowedBooks");
    }

}

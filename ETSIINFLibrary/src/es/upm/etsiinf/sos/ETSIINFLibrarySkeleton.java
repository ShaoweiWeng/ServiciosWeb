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
import java.util.List;
import java.util.ArrayList;
import java.util.logging.Logger;

import org.apache.axis2.AxisFault;
import org.apache.axis2.context.ServiceContext;
import org.apache.axis2.service.Lifecycle;

import es.upm.etsiinf.sos.model.xsd.Response;
import es.upm.etsiinf.sos.model.xsd.User;
import es.upm.etsiinf.sos.model.xsd.Book;
import es.upm.etsiinf.sos.model.xsd.MyUser;
import es.upm.fi.sos.t3.backend.UPMAuthenticationAuthorizationWSSkeletonStub;

/**
 * ETSIINFLibrarySkeleton java skeleton for the axisService
 */
public class ETSIINFLibrarySkeleton implements Lifecycle {
	private UPMAuthenticationAuthorizationWSSkeletonStub serviceStub;

	private static final MyUser ADMIN = new MyUser("admin", "admin");

	private MyUser userSession;

	private int sessionId;
	private int sessionCounter = 0;

	private Map<String, MyUser> registeredUsers = new HashMap<>();
	private Map<String, List<ETSIINFLibrarySkeleton>> activeUserSessions = new HashMap<>();

	private static final Logger logger = Logger.getLogger(ETSIINFLibrarySkeleton.class.getName());

	private static final List<Book> books = new ArrayList<>();
	private static final Map<String, Integer> ejemplares = new HashMap<>();
	private Map<User, List<Book>> prestamos = new HashMap<>();

	private boolean hasBorrowedBooks(String userName) {
		for (Map.Entry<User, List<Book>> entries : prestamos.entrySet()) {
			User user = entries.getKey();
			List<Book> bookList = entries.getValue();
			if (user.getName().equals(userName) && !bookList.isEmpty()) {
				return true;
			}
		}
		return false;
	}

	public void init(ServiceContext context) {
		context.getConfigurationContext().setProperty("ConfigContextTimeoutInterval", 600000);
		logger.info("Starting up instance " + sessionId);
		logger.info("The context timeout interval set is "
				+ context.getConfigurationContext().getServiceGroupContextTimeoutInterval());
	}

	public void destroy(ServiceContext context) {
		logger.info("Shutting down instance " + sessionId);
	}

	public ETSIINFLibrarySkeleton() throws AxisFault {
		sessionId = sessionCounter++;
		userSession = null;
		try {
			serviceStub = new UPMAuthenticationAuthorizationWSSkeletonStub();
		} catch (AxisFault e) {
			e.printStackTrace();
		}
	}

	/**
	 * Auto generated method signature
	 * 
	 * @param addUser
	 * @return addUserResponse
	 */

	public es.upm.etsiinf.sos.AddUserResponse addUser(es.upm.etsiinf.sos.AddUser addUser) {
		String userName = addUser.getArgs0().getUsername();

		AddUserResponse addUserResponse = new AddUserResponse();
		es.upm.etsiinf.sos.model.xsd.AddUserResponse response = new es.upm.etsiinf.sos.model.xsd.AddUserResponse();
		response.setResponse(false);

		if (userSession.equals(ADMIN) && !registeredUsers.containsKey(userName)) {
			try {
				UPMAuthenticationAuthorizationWSSkeletonStub.UserBackEnd userBackEnd = new UPMAuthenticationAuthorizationWSSkeletonStub.UserBackEnd();
				userBackEnd.setName(userName);

				UPMAuthenticationAuthorizationWSSkeletonStub.AddUser addUserRequest = new UPMAuthenticationAuthorizationWSSkeletonStub.AddUser();
				addUserRequest.setUser(userBackEnd);

				UPMAuthenticationAuthorizationWSSkeletonStub.AddUserResponse serviceResponse = serviceStub
						.addUser(addUserRequest);

				UPMAuthenticationAuthorizationWSSkeletonStub.AddUserResponseBackEnd backendResponse = serviceResponse
						.get_return();

				boolean result = backendResponse.getResult();
				response.setResponse(result);

				if (result) {
					response.setPwd(backendResponse.getPassword());
					registeredUsers.put(userName, new MyUser(userName, backendResponse.getPassword()));
					System.out.println("User added successfully: " + userName);
				} else {
					System.out.println("Adding user: " + userName + " operation failed");
				}
			} catch (RemoteException e) {
				e.printStackTrace();
			}
		} else {
			System.out.println("Only admin can add users / or user already exists");
		}
		addUserResponse.set_return(response);
		return addUserResponse;
	}

	/**
	 * Auto generated method signature
	 * 
	 * @param login
	 * @return loginResponse
	 */

	public es.upm.etsiinf.sos.LoginResponse login(es.upm.etsiinf.sos.Login login) {
		User user = login.getArgs0();
		String loginUserName = login.getArgs0().getName();
		String loginUserPwd = login.getArgs0().getPwd();

		LoginResponse loginResponse = new LoginResponse();
		Response response = new Response();
		response.setResponse(false);

		// Case 1: User is already logged in
		if (userSession != null) {
			if (loginUserName.equals(userSession.getUserName())) {
				response.setResponse(true);
				System.out.println("User: " + loginUserName + " is already logged in. SessionID: " + sessionId);
			} else {
				System.out.println("A different user is attempting to log in to the current session: " + loginUserName);
			}
			// Case 2: User is ADMIN and not logged in
		} else if (loginUserName.equals(ADMIN.getUserName()) && loginUserPwd.equals(ADMIN.getPassword())) {
			userSession = ADMIN;
			response.setResponse(true);
			System.out.println("Admin logged in successfully");
			// Case 3: User is not logged in
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

				boolean result = backendResponse.getResult();
				if (result) {
					if (!registeredUsers.containsKey(loginUserName)) {
						MyUser loginUser = new MyUser(loginUserName, loginUserPwd);
						registeredUsers.put(loginUserName, loginUser);
						userSession = loginUser;
						System.out.println("User: " + loginUserName
								+ " was not registered locally, added to local register and logged in successfully");
					} else {
						userSession = registeredUsers.get(loginUserName);
						System.out.println("User: " + loginUserName + " logged in successfully");
					}
					if (!activeUserSessions.containsKey(loginUserName)) {
						List<ETSIINFLibrarySkeleton> session = new ArrayList<>();
						session.add(this);
						activeUserSessions.put(loginUserName, session);
					} else {
						activeUserSessions.get(loginUserName).add(this);
					}
					response.setResponse(true);
				} else {
					System.out.println("Logging user: " + loginUserName + " operation failed");
				}
			} catch (RemoteException e) {
				System.out.println(e.getMessage());
			}
		}
		loginResponse.set_return(response);
		return loginResponse;
	}

	/**
	 * Auto generated method signature
	 * 
	 * @param logout
	 * @return logoutResponse
	 */

	public es.upm.etsiinf.sos.LogoutResponse logout(es.upm.etsiinf.sos.Logout logout) {
		LogoutResponse logoutResponse = new LogoutResponse();
		Response response = new Response();
		response.setResponse(false);

		String userName = userSession.getUserName();
		if (userName == null) {
			System.out.println("No user is logged in");
		} else {
			if (activeUserSessions.containsKey(userName)) {
				int sessions = activeUserSessions.get(userName).size();
				activeUserSessions.remove(userName);
				response.setResponse(true);
				System.out.println("User: " + userName + " logged out successfully. Removed sessions: " + sessions);
			}
			userSession = null;
		}
		logoutResponse.set_return(response);
		return logoutResponse;
	}

	/**
	 * Auto generated method signature
	 * 
	 * @param deleteUser
	 * @return deleteUserResponse
	 */

	public es.upm.etsiinf.sos.DeleteUserResponse deleteUser(es.upm.etsiinf.sos.DeleteUser deleteUser) {
		String userNameToDelete = deleteUser.getArgs0().getUsername();

		DeleteUserResponse deleteUserResponse = new DeleteUserResponse();
		Response response = new Response();
		response.setResponse(false);

		if (userNameToDelete.equals(ADMIN.getUserName())) {
			System.out.println("Cannot delete admin user");
		} else if (hasBorrowedBooks(userNameToDelete)) {
			System.out.println("User: " + userNameToDelete + " has books borrowed, can`t delete this user");
		} else if (userSession != null && userSession.getUserName().equals(ADMIN.getUserName())) {
			try {
				UPMAuthenticationAuthorizationWSSkeletonStub.UserBackEnd userBackEnd = new UPMAuthenticationAuthorizationWSSkeletonStub.UserBackEnd();
				userBackEnd.setName(userNameToDelete);

				UPMAuthenticationAuthorizationWSSkeletonStub.RemoveUser deleteUserRequest = new UPMAuthenticationAuthorizationWSSkeletonStub.RemoveUser();
				deleteUserRequest.setName(deleteUser.localArgs0.getUsername());
				deleteUserRequest.setPassword(registeredUsers.get(userNameToDelete).getPassword());

				UPMAuthenticationAuthorizationWSSkeletonStub.RemoveUserE deleteUserE = new UPMAuthenticationAuthorizationWSSkeletonStub.RemoveUserE();
				deleteUserE.setRemoveUser(deleteUserRequest);

				UPMAuthenticationAuthorizationWSSkeletonStub.RemoveUserResponseE serviceResponse = serviceStub
						.removeUser(deleteUserE);

				UPMAuthenticationAuthorizationWSSkeletonStub.RemoveUserResponse backendResponse = serviceResponse
						.get_return();

				boolean result = backendResponse.getResult();
				response.setResponse(result);

				if (result) {
					registeredUsers.remove(userNameToDelete);
					System.out.println("Local register of the user: " + userNameToDelete + " was deleted successfully");
					if (activeUserSessions.containsKey(userNameToDelete)) {
						activeUserSessions.remove(userNameToDelete);
					}
				}
			} catch (RemoteException e) {
				System.out.println(e.getMessage());
			}
		} else {
			System.out.println("Can`t delete this user");
		}
		deleteUserResponse.set_return(response);
		return deleteUserResponse;
	}

	/**
	 * Auto generated method signature
	 * 
	 * @param changePassword
	 * @return changePasswordResponse
	 */

	public es.upm.etsiinf.sos.ChangePasswordResponse changePassword(es.upm.etsiinf.sos.ChangePassword changePassword) {
		String oldPassword = changePassword.getArgs0().getOldpwd();
		String newPassword = changePassword.getArgs0().getNewpwd();

		ChangePasswordResponse changePwdResponse = new ChangePasswordResponse();
		Response response = new Response();
		response.setResponse(false);

		if (userSession.equals(ADMIN) && oldPassword.equals(ADMIN.getPassword())) {
			ADMIN.setPassword(newPassword);
			response.setResponse(true);
			System.out.println("Admin password changed successfully");
		} else if (userSession.getPassword().equals(oldPassword)) {
			try {
				UPMAuthenticationAuthorizationWSSkeletonStub.ChangePasswordBackEnd changePwdBackEnd = new UPMAuthenticationAuthorizationWSSkeletonStub.ChangePasswordBackEnd();
				changePwdBackEnd.setOldpwd(oldPassword);
				changePwdBackEnd.setNewpwd(newPassword);
				changePwdBackEnd.setName(userSession.getUserName());

				UPMAuthenticationAuthorizationWSSkeletonStub.ChangePassword changePwdRequest = new UPMAuthenticationAuthorizationWSSkeletonStub.ChangePassword();
				changePwdRequest.setChangePassword(changePwdBackEnd);

				UPMAuthenticationAuthorizationWSSkeletonStub.ChangePasswordResponseE serviceResponse = serviceStub
						.changePassword(changePwdRequest);

				UPMAuthenticationAuthorizationWSSkeletonStub.ChangePasswordResponse backendResponse = serviceResponse
						.get_return();

				boolean result = backendResponse.getResult();
				response.setResponse(result);

				if (result) {
					userSession.setPassword(newPassword);
					System.out.println("User password changed successfully");
				} else {
					System.out.println("User password changed failed");
				}
			} catch (RemoteException e) {
				System.out.println(e.getMessage());
			}
		} else {
			System.out.println("Not logged in or old password is wrong");
		}
		changePwdResponse.set_return(response);
		return changePwdResponse;
	}

	/**
	 * Auto generated method signature
	 * 
	 * @param borrowBook
	 * @return borrowBookResponse
	 */

	public es.upm.etsiinf.sos.BorrowBookResponse borrowBook(es.upm.etsiinf.sos.BorrowBook borrowBook) {
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

	public es.upm.etsiinf.sos.ReturnBookResponse returnBook(es.upm.etsiinf.sos.ReturnBook returnBook) {
		// TODO : fill this with the necessary business logic
		throw new java.lang.UnsupportedOperationException(
				"Please implement " + this.getClass().getName() + "#returnBook");
	}

	/**
	 * Auto generated method signature
	 * 
	 * @param removeBook
	 * @return removeBookResponse
	 */

	public es.upm.etsiinf.sos.RemoveBookResponse removeBook(es.upm.etsiinf.sos.RemoveBook removeBook) {
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
						logger.info(
								"Ejemplar eliminado, quedan " + (numEjemplares - 1) + " ejemplares de ISSN: " + issn);
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
	 * @param getBook
	 * @return getBookResponse
	 */

	public es.upm.etsiinf.sos.GetBookResponse getBook(es.upm.etsiinf.sos.GetBook getBook) {
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

	public es.upm.etsiinf.sos.ListBooksResponse listBooks(es.upm.etsiinf.sos.ListBooks listBooks) {
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
	 * @param addBook
	 * @return addBookResponse
	 */

	public es.upm.etsiinf.sos.AddBookResponse addBook(es.upm.etsiinf.sos.AddBook addBook) {
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

		boolean valid = name != null && !name.trim().isEmpty() && issn != null && !issn.trim().isEmpty()
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

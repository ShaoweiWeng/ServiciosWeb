package es.upm.etsiinf.sos;

import es.upm.etsiinf.sos.ETSIINFLibraryStub.AddUser;
import es.upm.etsiinf.sos.ETSIINFLibraryStub.AddUserResponseE;
import es.upm.etsiinf.sos.ETSIINFLibraryStub.Book;
import es.upm.etsiinf.sos.ETSIINFLibraryStub.ChangePassword;
import es.upm.etsiinf.sos.ETSIINFLibraryStub.ChangePasswordResponse;
import es.upm.etsiinf.sos.ETSIINFLibraryStub.DeleteUser;
import es.upm.etsiinf.sos.ETSIINFLibraryStub.DeleteUserResponse;
import es.upm.etsiinf.sos.ETSIINFLibraryStub.Login;
import es.upm.etsiinf.sos.ETSIINFLibraryStub.LoginResponse;
import es.upm.etsiinf.sos.ETSIINFLibraryStub.Logout;
import es.upm.etsiinf.sos.ETSIINFLibraryStub.PasswordPair;
import es.upm.etsiinf.sos.ETSIINFLibraryStub.User;
import es.upm.etsiinf.sos.ETSIINFLibraryStub.Username;
import es.upm.etsiinf.sos.ETSIINFLibraryStub.AddBook;
import es.upm.etsiinf.sos.ETSIINFLibraryStub.RemoveBook;
import es.upm.etsiinf.sos.ETSIINFLibraryStub.GetBook;
import es.upm.etsiinf.sos.ETSIINFLibraryStub.ListBooks;
import es.upm.etsiinf.sos.ETSIINFLibraryStub.ListBooksResponse;

import java.rmi.RemoteException;

public class ClientETSIINFLibrary {
	private static ETSIINFLibraryStub stub;

	public static void main(String[] args) throws Exception {
		stub = new ETSIINFLibraryStub();
		stub._getServiceClient().getOptions().setManageSession(true);
		stub._getServiceClient().engageModule("addressing");

		loginAsAdmin();
		logout();

		loginAsUser("yujie.weng", "yujie.weng1234");
		loginAsUser("yujie.weng", "yujie.weng1234");
		logout();

		loginAsAdmin();
		addNewUser("changePasswordTest");
		addNewUser("deleteUserTest");
		deleteUser("deleteUserTest");
		logout();

		loginAsUser("changePasswordTest", "changePasswordTestNewPassword");
		changePassword("changePasswordTestNewPassword", "changePasswordTestNewPassword");
		logout();

		testAddBook();
		testRemoveBook();
		testGetBook();
		testListBooks();

	}

	private static void loginAsAdmin() throws RemoteException {
		Login login = new Login();
		User user = new User();
		user.setName("admin");
		user.setPwd("admin");
		login.setArgs0(user);

		try {
			LoginResponse loginResponse = stub.login(login);
			if (loginResponse.get_return().getResponse()) {
				System.out.println("Admin login successful");
			} else {
				System.out.println("Admin login failed");
			}
		} catch (RemoteException e) {
			System.out.println("Error: " + e.getMessage());
		}
	}

	private static void addNewUser(String userName) throws RemoteException {
		AddUser addUser = new AddUser();
		Username user = new Username();
		user.setUsername(userName);
		addUser.setArgs0(user);

		try {
			AddUserResponseE addUserResponse = stub.addUser(addUser);
			if (addUserResponse.get_return().getResponse()) {
				System.out.println("User: " + userName + " added successfully");
				System.out.println("Password: " + addUserResponse.get_return().getPwd());
			} else {
				System.out.println("Adding user failed");
			}
		} catch (RemoteException e) {
			e.printStackTrace();
		}
	}

	private static void loginAsUser(String userName, String password) throws RemoteException {
		Login login = new Login();
		User user = new User();
		user.setName(userName);
		user.setPwd(password);
		login.setArgs0(user);

		try {
			LoginResponse loginResponse = stub.login(login);
			if (loginResponse.get_return().getResponse()) {
				System.out.println("User: " + userName + " logged in successfully");
			} else {
				System.out.println("User login failed");
			}
		} catch (RemoteException e) {
			e.printStackTrace();
		}
	}

	private static void logout() throws RemoteException {
		try {
			Logout logout = new Logout();
			stub.logout(logout);
			System.out.println("Logout successful");
		} catch (RemoteException e) {
			e.printStackTrace();
		}
	}

	private static void deleteUser(String userName) throws RemoteException {
		DeleteUser deleteUser = new DeleteUser();
		Username user = new Username();
		user.setUsername(userName);
		deleteUser.setArgs0(user);

		try {
			DeleteUserResponse deleteUserResponse = stub.deleteUser(deleteUser);
			if (deleteUserResponse.get_return().getResponse()) {
				System.out.println("User: " + userName + " deleted successfully");
			} else {
				System.out.println("Deleting user failed");
			}
		} catch (RemoteException e) {
			e.printStackTrace();
		}
	}

	private static void changePassword(String oldPassword, String newPassword) throws RemoteException {
		ChangePassword changePassword = new ChangePassword();
		PasswordPair passwordPair = new PasswordPair();
		passwordPair.setOldpwd(oldPassword);
		passwordPair.setNewpwd(newPassword);
		changePassword.setArgs0(passwordPair);

		try {
			ChangePasswordResponse response = stub.changePassword(changePassword);
			if (response.get_return().getResponse()) {
				System.out.println("Password changed successfully");
			} else {
				System.out.println("Changing password failed");
			}
		} catch (RemoteException e) {
			e.printStackTrace();
		}
	}

	private static void testAddBook() throws RemoteException {
		System.out.println("\n--- testAddBook ---");
		// 1. Añadir libro como admin
		System.out.println("---AddBook exitoso como admin---");
		loginAsAdmin();
		Book book = new Book();
		book.setName("LibroTest");
		book.setISSN("1234567890");
		book.setAuthors(new String[] { "Autor1", "Autor2" });
		AddBook addBook = new AddBook();
		addBook.setArgs0(book);
		boolean added = stub.addBook(addBook).get_return().getResponse();
		System.out.println("Admin añade libro: " + (added ? "OK" : "FAIL"));
		logout();

		// 2. Añadir libro como usuario no admin
		System.out.println("---AddBook como usuario no admin, debe fallar---");
		loginAsUser("changePasswordTest", "changePasswordTestNewPassword");
		AddBook addBook2 = new AddBook();
		Book book2 = new Book();
		book2.setName("LibroTest2");
		book2.setISSN("0987654321");
		book2.setAuthors(new String[] { "Autor3" });
		addBook2.setArgs0(book2);
		boolean added2 = stub.addBook(addBook2).get_return().getResponse();
		System.out.println("Usuario no admin añade libro: " + (added2 ? "OK" : "FAIL"));
		logout();

		// 3. Añadir libro con datos incompletos
		System.out.println("---AddBook con datos incompletos, debe fallar---");
		loginAsAdmin();
		AddBook addBook3 = new AddBook();
		Book book3 = new Book();
		book3.setName(""); // nombre vacío
		book3.setISSN(""); // ISSN vacío
		book3.setAuthors(new String[] {}); // autores vacío
		addBook3.setArgs0(book3);
		boolean added3 = stub.addBook(addBook3).get_return().getResponse();
		System.out.println("Admin añade libro con datos incompletos: " + (added3 ? "OK" : "FAIL"));

		// 4. Añadir libro que ya existe
		System.out.println("---AddBook duplicado, exitoso debe añadir ejemplar---");
		Book book4 = new Book();
		book4.setName("LibroTest");
		book4.setISSN("1234567890");
		book4.setAuthors(new String[] { "Autor1", "Autor2" });
		AddBook addBook4 = new AddBook();
		addBook4.setArgs0(book4);
		boolean added4 = stub.addBook(addBook4).get_return().getResponse();
		System.out.println("Admin añade libro duplicado: " + (added4 ? "OK" : "FAIL"));
		logout();
	}

	private static void testRemoveBook() throws RemoteException {
		System.out.println("\n--- testRemoveBook ---");
		// 1. Eliminar libro como admin
		System.out.println("---RemoveBook exitoso como admin---");
		loginAsAdmin();
		RemoveBook removeBook = new RemoveBook();
		removeBook.setArgs0("1234567890");
		boolean removed = stub.removeBook(removeBook).get_return().getResponse();
		System.out.println("Admin elimina libro: " + (removed ? "OK" : "FAIL"));
		logout();

		// 2. Eliminar libro como usuario no admin
		System.out.println("---RemoveBook como usuario no admin, debe fallar---");
		loginAsUser("changePasswordTest", "changePasswordTestNewPassword");
		RemoveBook removeBook2 = new RemoveBook();
		removeBook2.setArgs0("0987654321");
		boolean removed2 = stub.removeBook(removeBook2).get_return().getResponse();
		System.out.println("Usuario no admin elimina libro: " + (removed2 ? "OK" : "FAIL"));
		logout();

		// 3. Eliminar libro que no existe
		System.out.println("---RemoveBook de libro inexistente, debe fallar---");
		loginAsAdmin();
		RemoveBook removeBook3 = new RemoveBook();
		removeBook3.setArgs0("noexiste");
		boolean removed3 = stub.removeBook(removeBook3).get_return().getResponse();
		System.out.println("Admin elimina libro inexistente: " + (removed3 ? "OK" : "FAIL"));
		logout();
	}

	private static void testGetBook() throws RemoteException {
		System.out.println("\n--- testGetBook ---");
		// 1. Obtener libro existente
		System.out.println("---GetBook existente---");
		loginAsAdmin();
		AddBook addBook = new AddBook();
		Book book = new Book();
		book.setName("LibroGet");
		book.setISSN("1111111111");
		book.setAuthors(new String[] { "AutorGet1", "AutorGet2", "AutorGet3" });
		addBook.setArgs0(book);
		stub.addBook(addBook);
		GetBook getBook = new GetBook();
		getBook.setArgs0("1111111111");
		Book result = stub.getBook(getBook).get_return();
		System.out.println("Nombre: " + result.getName());
		System.out.println("ISSN: " + result.getISSN());
		System.out.print("Autores: ");
		if (result.getAuthors() != null && result.getAuthors().length > 0) {
			for (int i = 0; i < result.getAuthors().length; i++) {
				System.out.print(result.getAuthors()[i]);
				if (i < result.getAuthors().length - 1) {
					System.out.print(", ");
				}
			}
			System.out.println();
		} else {
			System.out.println("null");
		}

		// 2. Obtener libro inexistente
		GetBook getBook2 = new GetBook();
		getBook2.setArgs0("noexiste");
		Book result2 = stub.getBook(getBook2).get_return();
		System.out.println(
				"---GetBook inexistente---\n"
						+ "Nombre: " + (result2 != null && result2.getName() != null ? result2.getName() : "null")
						+ "\n"
						+ "ISSN: " + (result2 != null && result2.getISSN() != null ? result2.getISSN() : "null") + "\n"
						+ "Autores: "
						+ (result2 != null && result2.getAuthors() != null && result2.getAuthors()[0] != null
								? result2.getAuthors()[0]
								: "null"));
		logout();

		// 3. Obtener libro sin autenticación
		GetBook getBook3 = new GetBook();
		getBook3.setArgs0("1111111111");
		Book result3 = stub.getBook(getBook3).get_return();
		System.out.println("---GetBook sin autenticación---\n"
				+ "Nombre: " + (result3 != null && result3.getName() != null ? result3.getName() : "null") + "\n"
				+ "ISSN: " + (result3 != null && result3.getISSN() != null ? result3.getISSN() : "null") + "\n"
				+ "Autores: "
				+ (result3 != null && result3.getAuthors() != null && result3.getAuthors()[0] != null
						? result3.getAuthors()[0]
						: "null"));
	}

	private static void testListBooks() throws RemoteException {
		System.out.println("\n--- testListBooks ---");
		// 1. Listar libros autenticado
		System.out.println("---ListBooks autenticado---");
		loginAsAdmin();
		ListBooks listBooks = new ListBooks();
		ListBooksResponse response = stub.listBooks(listBooks);
		String[] books = response.get_return().getBookNames();
		for (String libro : books) {
			System.out.println("Libro:" + libro + "\n");
		}
		logout();

		// 2. Listar libros sin autenticación
		System.out.println("---ListBooks sin autenticación---");
		ListBooks listBooks2 = new ListBooks();
		ListBooksResponse response2 = stub.listBooks(listBooks2);
		String[] books2 = response2.get_return().getBookNames();
		System.out.println(books2);
	}
}
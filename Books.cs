namespace Prezentacja;
public class Book
{
    public int Id { get; set; }
    public string Title { get; set; }
    public Book(int Id, string Title) 
    {
        this.Id = Id;
        this.Title = Title;
    }
}


public class Books
{
    private List<Book> books = new List<Book>();

    public Book Get(int id)
    {
        var book = books
            .Find(x => x.Id == id);
        return book;
    }
    public List<Book> Get()
    {
        return books;
    }
    public void Add(Book book)
    {
        books.Add(book);
    }

    public void Update(Book book)
    {
        books.Where(i => i.Id == book.Id).First().Title = book.Title;
    }

    public void Delete(int id)
    {
        books.RemoveAll(i => i.Id == id);
    }

}

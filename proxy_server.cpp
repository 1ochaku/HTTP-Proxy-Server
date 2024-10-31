#include <boost/asio.hpp>
#include <iostream>
#include <regex>
#include <unordered_map>
#include <string>

using boost::asio::ip::tcp;

class ProxyServer
{
public:
    ProxyServer(boost::asio::io_context &io_context, short port)
        : acceptor_(io_context, tcp::endpoint(tcp::v4(), port))
    {
        startAccept();
    }

private:
    // Structure: clientCookies[clientId][domainName][cookieName] = cookieValue
    // clientId = IP address + Port
    std::unordered_map<std::string, std::unordered_map<std::string, std::unordered_map<std::string, std::string>>> clientCookies;

    // Getting the unique identifier
    std::string getClientId(const boost::asio::ip::tcp::socket &socket)
    {
        auto remote_endpoint = socket.remote_endpoint();
        std::string clientIp = remote_endpoint.address().to_string();
        unsigned short clientPort = remote_endpoint.port();
        return clientIp + ":" + std::to_string(clientPort);
    }

    // Listens to the incoming requests and make a socket for that
    void startAccept()
    {
        auto newSession = std::make_shared<tcp::socket>(acceptor_.get_executor());
        acceptor_.async_accept(*newSession, [this, newSession](boost::system::error_code ec)
                               {
            if (!ec)
            {
                handleRequest(newSession);
            }
            startAccept(); });
    }

    // For trimming the white spaces
    std::string trim(const std::string &str)
    {
        size_t start = str.find_first_not_of(" \t\r\n");
        size_t end = str.find_last_not_of(" \t\r\n");
        return (start == std::string::npos || end == std::string::npos) ? "" : str.substr(start, end - start + 1);
    }

    // For separating the port number and domain names and setting the path as well
    bool parseRequest(const std::string &requestLine, std::istream &headerStream, std::string &host, std::string &path, std::string &version, std::string &port)
    {
        std::string method;
        std::istringstream requestStream(requestLine);
        requestStream >> method >> path >> version;

        // Remove "http://" prefix if present
        if (path.find("http://") == 0)
        {
            path = path.substr(7);
        }

        // Extract the path from the URL
        size_t pathStart = path.find('/');
        if (pathStart != std::string::npos)
        {
            path = path.substr(pathStart);
        }
        else
        {
            path = "/"; // Default path if none is specified
        }

        // Ensure the path starts with "/"
        if (path.empty() || path[0] != '/')
        {
            path = "/" + path;
        }

        // sets the host and port
        std::string headerLine;
        while (std::getline(headerStream, headerLine) && headerLine != "\r")
        {
            if (headerLine.find("Host: ") == 0)
            {
                std::string hostLine = headerLine.substr(6);
                size_t colonPos = hostLine.find(':');
                if (colonPos != std::string::npos)
                {
                    host = hostLine.substr(0, colonPos);
                    port = hostLine.substr(colonPos + 1);
                }
                else
                {
                    host = hostLine;
                }
            }
        }

        // Default to port 80 if none is specified
        if (port.empty())
        {
            port = "80";
        }

        // Trim host and port
        host = trim(host);
        port = trim(port);

        return !host.empty();
    }

    // Function to forward the request to the target server and handle the response
    void forwardRequest(std::shared_ptr<tcp::socket> clientSocket, const std::string &host, const std::string &path, const std::string &version, const std::string &port)
    {
        // creating a server socket
        auto serverSocket = std::make_shared<tcp::socket>(clientSocket->get_executor());

        // resolving the domain name to ip address
        tcp::resolver resolver(clientSocket->get_executor());
        boost::system::error_code resolveError;
        auto endpoints = resolver.resolve(host, port, resolveError);

        // if resolving fails
        if (resolveError)
        {
            std::cerr << "DNS resolution failed: " << resolveError.message() << std::endl;
            return;
        }

        std::cout << "DNS resolution successful. Connecting to the first endpoint..." << std::endl;

        // it connects to resolved ip address using the above server socket created
        boost::asio::async_connect(*serverSocket, endpoints, [this, clientSocket, serverSocket, path, version, host, port](boost::system::error_code ec, tcp::endpoint endpoint)
                                   {
        if (!ec) {
            std::cout << "Connected to server." << std::endl;

            // as http request is forwarded this way so formatting
            std::string forwardRequest = "GET " + path + " " + version + "\r\n" +
                                         "Host: " + host + "\r\n" +
                                         "Connection: close\r\n\r\n";

            // sends the request to the server through the socket created
            boost::asio::async_write(*serverSocket, boost::asio::buffer(forwardRequest), [this, clientSocket, serverSocket](boost::system::error_code ec, std::size_t) {
                if (!ec) {
                    std::cout << "Request forwarded to server." << std::endl;

                    auto responseBuffer = std::make_shared<boost::asio::streambuf>();
                    auto accumulatedResponse = std::make_shared<std::string>();

                    // Initiate reading response from the server
                    readServerResponse(clientSocket, serverSocket, responseBuffer, accumulatedResponse);
                } else {
                    std::cerr << "Error forwarding request to server: " << ec.message() << std::endl;
                }
            });
        } else {
            std::cerr << "Error connecting to server: " << ec.message() << std::endl;
        } });
    }

    // Function to continuously read from the server and accumulate data
    void readServerResponse(std::shared_ptr<tcp::socket> clientSocket, std::shared_ptr<tcp::socket> serverSocket, std::shared_ptr<boost::asio::streambuf> responseBuffer, std::shared_ptr<std::string> accumulatedResponse)
    {
        // continously read the response called by forwardRequest as servers send in the format of packets
        boost::asio::async_read(*serverSocket, *responseBuffer, boost::asio::transfer_at_least(1),
                                [this, clientSocket, serverSocket, responseBuffer, accumulatedResponse](boost::system::error_code ec, std::size_t bytesTransferred)
                                {
                                    if (!ec || ec == boost::asio::error::eof)
                                    {
                                        // Append data to the accumulated response string
                                        std::istream responseStream(responseBuffer.get());
                                        accumulatedResponse->append(std::istreambuf_iterator<char>(responseStream), std::istreambuf_iterator<char>());

                                        // Check if more data is coming or we are done
                                        if (ec == boost::asio::error::eof)
                                        {
                                            std::cout << "Complete response received:\n"
                                                      << *accumulatedResponse << std::endl;

                                            // Process the complete accumulated response here
                                            processAndForwardResponse(clientSocket, *accumulatedResponse);
                                        }
                                        else
                                        {
                                            // Continue reading from the server
                                            readServerResponse(clientSocket, serverSocket, responseBuffer, accumulatedResponse);
                                        }
                                    }
                                    else
                                    {
                                        std::cerr << "Error receiving response from server: " << ec.message() << " (Code: " << ec.value() << ")" << std::endl;
                                    }
                                });
    }

    // Function to process the accumulated response and forward it to the client
    void processAndForwardResponse(std::shared_ptr<tcp::socket> clientSocket, const std::string &responseContent)
    {
        // Separate headers and body based on "\r\n\r\n"
        auto headerEndPos = responseContent.find("\r\n\r\n");
        if (headerEndPos != std::string::npos)
        {
            std::string headerContent = responseContent.substr(0, headerEndPos);
            std::string bodyContent = responseContent.substr(headerEndPos + 4); // +4 to skip past "\r\n\r\n"

            // Formating the header
            headerContent = "HTTP/1.1 200 OK\r\n"
                            "Content-Length: " +
                            std::to_string(bodyContent.size()) + "\r\n"
                                                                 "Connection: close\r\n"
                                                                 "Content-Type: text/html\r\n"
                                                                 "\r\n"; // End of headers

            // Debugging output
            std::cout << "Headers:\n"
                      << headerContent << std::endl;

            // Send headers to client
            boost::asio::async_write(*clientSocket, boost::asio::buffer(headerContent),
                                     [clientSocket, headerContent](boost::system::error_code ec, std::size_t bytesTransferred)
                                     {
                                         if (!ec)
                                         {
                                             std::cout << "Header sent to client. Bytes transferred: " << bytesTransferred << std::endl;
                                         }
                                         else
                                         {
                                             std::cerr << "Error sending header to client: " << ec.message() << std::endl;
                                             if (ec == boost::asio::error::operation_aborted)
                                             {
                                                 std::cerr << "Write operation was aborted." << std::endl;
                                             }
                                             else if (ec == boost::asio::error::eof)
                                             {
                                                 std::cerr << "Connection closed by peer." << std::endl;
                                             }
                                         }
                                     });

            // Extract and trim Transfer-Encoding header: as can be sent in the form of chunks
            std::string transferEncoding;
            std::istringstream headerStream(headerContent);
            std::string line;
            while (std::getline(headerStream, line))
            {
                if (line.find("Transfer-Encoding:") == 0)
                {
                    transferEncoding = line.substr(line.find(':') + 1);
                    transferEncoding.erase(transferEncoding.find_last_not_of(" \t") + 1);
                    break;
                }
            }

            transferEncoding = trim(transferEncoding); // Remove extra spaces

            if (transferEncoding == "chunked")
            {
                std::cout << "Processing chunked encoding." << std::endl;
                std::string decodedContent;

                // Process the chunked data
                std::string chunkedData = bodyContent;
                while (!chunkedData.empty())
                {
                    auto chunkSizeEnd = chunkedData.find("\r\n");
                    if (chunkSizeEnd == std::string::npos)
                        break; // Invalid chunk format

                    std::string chunkSizeStr = chunkedData.substr(0, chunkSizeEnd);
                    chunkSizeStr.erase(chunkSizeStr.find_last_not_of(" \r\n\t") + 1);

                    try
                    {
                        std::size_t chunkSize = std::stoul(chunkSizeStr, nullptr, 16);
                        if (chunkSize == 0)
                            break; // End of chunked transfer

                        std::string chunkData = chunkedData.substr(chunkSizeEnd + 2, chunkSize);
                        decodedContent += chunkData;
                        chunkedData = chunkedData.substr(chunkSizeEnd + 2 + chunkSize + 2);
                    }
                    catch (const std::exception &e)
                    {
                        std::cerr << "Error parsing chunk size: " << e.what() << std::endl;
                        break;
                    }
                }

                std::cout << "Decoded chunked data:\n"
                          << decodedContent << std::endl;

                // Send the decoded content to the client
                boost::asio::async_write(*clientSocket, boost::asio::buffer(decodedContent),
                                         [clientSocket, decodedContent](boost::system::error_code ec, std::size_t bytesTransferred)
                                         {
                                             if (!ec)
                                             {
                                                 std::cout << "Response sent to client. Bytes transferred: " << bytesTransferred << std::endl;
                                             }
                                             else
                                             {
                                                 std::cerr << "Error sending response to client: " << ec.message() << std::endl;
                                                 if (ec == boost::asio::error::operation_aborted)
                                                 {
                                                     std::cerr << "Write operation was aborted." << std::endl;
                                                 }
                                                 else if (ec == boost::asio::error::eof)
                                                 {
                                                     std::cerr << "Connection closed by peer." << std::endl;
                                                 }
                                             }
                                         });
            }
            else
            {
                // Send non-chunked data directly
                boost::asio::async_write(*clientSocket, boost::asio::buffer(bodyContent),
                                         [clientSocket, bodyContent](boost::system::error_code ec, std::size_t bytesTransferred)
                                         {
                                             if (!ec)
                                             {
                                                 std::cout << "Response sent to client. Bytes transferred: " << bytesTransferred << std::endl;
                                             }
                                             else
                                             {
                                                 std::cerr << "Error sending response to client: " << ec.message() << std::endl;
                                                 if (ec == boost::asio::error::operation_aborted)
                                                 {
                                                     std::cerr << "Write operation was aborted." << std::endl;
                                                 }
                                                 else if (ec == boost::asio::error::eof)
                                                 {
                                                     std::cerr << "Connection closed by peer." << std::endl;
                                                 }
                                             }
                                         });
            }
        }
        else
        {
            std::cerr << "Error: Could not find the end of headers." << std::endl;
        }
    }

    // Main handleRequest function that coordinates the request parsing and forwarding
    void handleRequest(std::shared_ptr<tcp::socket> clientSocket)
    {
        auto buffer = std::make_shared<boost::asio::streambuf>();

        // receives the request from the client
        boost::asio::async_read_until(*clientSocket, *buffer, "\r\n\r\n", [this, clientSocket, buffer](boost::system::error_code ec, std::size_t)
                                      {
        if (!ec) {
            std::istream headerStream(buffer.get());
            std::string requestLine;
            std::getline(headerStream, requestLine);

            std::cout << "Received request line: " << requestLine << std::endl;

            std::string host, path, version, port;

            // after parsing, send it to forwardRequest function
            if (parseRequest(requestLine, headerStream, host, path, version, port)) {
                std::cout << "Extracted path: " << path << std::endl;
                std::cout << "Attempting to connect to server: " << host << ":" << port << std::endl;
                forwardRequest(clientSocket, host, path, version, port);
            } else {
                std::cerr << "Host header missing or invalid request format." << std::endl;
            }
        } else {
            std::cerr << "Error reading request headers: " << ec.message() << std::endl;
        } });
    }

    tcp::acceptor acceptor_;
};

int main()
{
    try
    {
        boost::asio::io_context io_context;
        ProxyServer server(io_context, 8080); // Listen on port 8080
        io_context.run();
    }
    catch (std::exception &e)
    {
        std::cerr << "Exception: " << e.what() << "\n";
    }
    return 0;
}

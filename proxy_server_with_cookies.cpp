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
        // Fixed port number for consistency
        std::string fixedPort = "80";
        return clientIp + ":" + fixedPort;
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
                                         "Host: " + host + "\r\n";

            // Add cookies to the request
            addCookiesToRequest(forwardRequest, getClientId(*clientSocket), host);

            forwardRequest += "Connection: close\r\n\r\n";

            // sends the request to the server through the socket created
            boost::asio::async_write(*serverSocket, boost::asio::buffer(forwardRequest), [this, clientSocket, serverSocket, host](boost::system::error_code ec, std::size_t) {
                if (!ec) {
                    std::cout << "Request forwarded to server." << std::endl;

                    auto responseBuffer = std::make_shared<boost::asio::streambuf>();
                    auto accumulatedResponse = std::make_shared<std::string>();

                    // Initiate reading response from the server
                    readServerResponse(clientSocket, serverSocket, responseBuffer, accumulatedResponse, host);
                } else {
                    std::cerr << "Error forwarding request to server: " << ec.message() << std::endl;
                }
            });
        } else {
            std::cerr << "Error connecting to server: " << ec.message() << std::endl;
        } });
    }

    // Function to continuously read from the server and accumulate data
    void readServerResponse(std::shared_ptr<tcp::socket> clientSocket, std::shared_ptr<tcp::socket> serverSocket, std::shared_ptr<boost::asio::streambuf> responseBuffer, std::shared_ptr<std::string> accumulatedResponse, const std::string &domain)
    {
        // continuously read the response called by forwardRequest as servers send in the format of packets
        boost::asio::async_read(*serverSocket, *responseBuffer, boost::asio::transfer_at_least(1),
                                [this, clientSocket, serverSocket, responseBuffer, accumulatedResponse, domain](boost::system::error_code ec, std::size_t bytesTransferred)
                                {
                                    if (!ec || ec == boost::asio::error::eof)
                                    {
                                        // Append data to the accumulated response string
                                        std::istream responseStream(responseBuffer.get());
                                        accumulatedResponse->append(std::istreambuf_iterator<char>(responseStream), std::istreambuf_iterator<char>());

                                        // Check if more data is coming or we are done
                                        if (ec == boost::asio::error::eof)
                                        {
                                            // std::cout << "Complete response received:\n"
                                            //<< *accumulatedResponse << std::endl;

                                            // Process the complete accumulated response here
                                            processAndForwardResponse(clientSocket, *accumulatedResponse, domain);
                                        }
                                        else
                                        {
                                            // Continue reading from the server
                                            readServerResponse(clientSocket, serverSocket, responseBuffer, accumulatedResponse, domain);
                                        }
                                    }
                                    else
                                    {
                                        std::cerr << "Error receiving response from server: " << ec.message() << " (Code: " << ec.value() << ")" << std::endl;
                                    }
                                });
    }

    // Function to process the accumulated response and forward it to the client
    void processAndForwardResponse(std::shared_ptr<tcp::socket> clientSocket, const std::string &responseContent, const std::string &domain)
    {
        // Separate headers and body based on "\r\n\r\n"
        auto headerEndPos = responseContent.find("\r\n\r\n");
        if (headerEndPos == std::string::npos)
        {
            std::cerr << "Malformed response: missing header-body separator." << std::endl;
            return;
        }

        std::string headers = responseContent.substr(0, headerEndPos + 4);
        std::string body = responseContent.substr(headerEndPos + 4);

        // std::cout << "Extracted Headers:\n"
        //<< headers << std::endl;

        // Store cookies if any found in the response headers
        storeCookiesFromResponse(headers, getClientId(*clientSocket), domain);

        // Reconstruct the full response to forward to the client
        std::string fullResponse = headers + body;

        // Forward the full response to the client
        boost::asio::async_write(*clientSocket, boost::asio::buffer(fullResponse), [clientSocket](boost::system::error_code ec, std::size_t bytesSent)
                                 {
                                     if (!ec)
                                     {
                                         std::cout << "Response forwarded to client successfully." << std::endl;
                                     }
                                     else
                                     {
                                         std::cerr << "Error sending response to client: " << ec.message() << std::endl;
                                     } });
    }

    // Extract cookies from server response headers and store them for the client
    void storeCookiesFromResponse(const std::string &headers, const std::string &clientId, const std::string &domain)
    {
        std::regex setCookieRegex(R"(Set-Cookie:\s*([^=]+)=([^;]+);?)", std::regex::icase);
        std::sregex_iterator cookiesBegin(headers.begin(), headers.end(), setCookieRegex);
        std::sregex_iterator cookiesEnd;

        for (auto it = cookiesBegin; it != cookiesEnd; ++it)
        {
            std::string cookieName = it->str(1);
            std::string cookieValue = it->str(2);

            clientCookies[clientId][domain][cookieName] = cookieValue;
            std::cout << "Stored cookie for client " << clientId << ": " << cookieName << "=" << cookieValue << std::endl;
        }
    }

    // Add stored cookies to the request headers before sending to the server
    void addCookiesToRequest(std::string &request, const std::string &clientId, const std::string &domain)
    {
        if (clientCookies.find(clientId) != clientCookies.end() && clientCookies[clientId].find(domain) != clientCookies[clientId].end())
        {
            const auto &cookies = clientCookies[clientId][domain];
            std::string cookieHeader = "Cookie: ";
            bool cookiesPresent = false;
            for (const auto &[cookieName, cookieValue] : cookies)
            {
                cookieHeader += cookieName + "=" + cookieValue + "; ";
                cookiesPresent = true;
            }
            if (cookiesPresent)
            {
                request += cookieHeader + "\r\n";
                std::cout << "Added cookies to request: " << cookieHeader << std::endl;
                std::cout << "Cookies are present for client " << clientId << " and domain " << domain << std::endl;
            }
            else
            {
                std::cout << "No cookies found for client " << clientId << " and domain " << domain << std::endl;
            }
        }
        else
        {
            std::cout << "No cookies found for client " << clientId << " and domain " << domain << std::endl;
        }
    }

    // Main handleRequest function that coordinates the request parsing and forwarding
    void handleRequest(std::shared_ptr<tcp::socket> clientSocket)
    {
        auto requestBuffer = std::make_shared<boost::asio::streambuf>();

        boost::asio::async_read_until(*clientSocket, *requestBuffer, "\r\n\r\n", [this, clientSocket, requestBuffer](boost::system::error_code ec, std::size_t)
                                      {
            if (!ec)
            {
                std::istream requestStream(requestBuffer.get());
                std::string requestLine;
                std::getline(requestStream, requestLine);
                requestLine = trim(requestLine);

                std::cout << "Received request line: " << requestLine << std::endl;

                std::string host, path, version, port;
                if (parseRequest(requestLine, requestStream, host, path, version, port))
                {
                    std::cout << "Parsed host: " << host << ", path: " << path << ", version: " << version << ", port: " << port << std::endl;
                    forwardRequest(clientSocket, host, path, version, port);
                }
                else
                {
                    std::cerr << "Invalid request: Could not parse host." << std::endl;
                }
            }
            else
            {
                std::cerr << "Error reading request: " << ec.message() << std::endl;
            } });
    }

    tcp::acceptor acceptor_;
};

int main()
{
    try
    {
        boost::asio::io_context io_context;
        ProxyServer server(io_context, 8080);
        io_context.run();
    }
    catch (std::exception &e)
    {
        std::cerr << "Exception: " << e.what() << "\n";
    }

    return 0;
}

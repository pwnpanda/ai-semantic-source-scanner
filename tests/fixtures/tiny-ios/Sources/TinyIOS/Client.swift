import Foundation

final class Client {
    func load(url: String) {
        URLSession.shared.dataTask(with: URL(string: url)!).resume()
    }
}

public extension Array where Element : AnyObject {

	public func indexByPointerComparing(of element: Element) -> Int? {
		var index: Int?

		for (indexInArray, elementInArray) in self.enumerated() {
			if element === elementInArray {
				index = indexInArray
				break
			}
		}

		return index
	}

	public mutating func removeByPointerComparing(element: Element) {
		if let index = self.indexByPointerComparing(of: element) {
			self.remove(at: index)
		}
	}

    public mutating func removeByPointerComparing(elements: [Element]) {
        guard elements.count > 0 else { return }
        for element in elements {
            self.removeByPointerComparing(element: element)
        }
    }

	public mutating func replace(at index: Int, with object: Element) {
		guard self.isIndexValid(index: index) else { return }

		self[index] = object
	}

}

public extension Array {

	func insert(separator: Element) -> [Element] {
		return (0 ..< 2 * self.count - 1).map { $0 % 2 == 0 ? self[$0/2] : separator }
	}

	public func isIndexValid(index: Int) -> Bool {
		return index >= 0 && index < self.count
	}

	public func safeObject(at index: Int) -> Element? {
		guard self.isIndexValid(index: index) else { return nil }
		return self[index]
	}

	public func groupBy<Key : Hashable, Item>(_ fn:(Item) -> Key) -> [Group<Key,Item>] {
		return self.groupBy(fn, matchWith: nil, valueAs: nil)
	}

	public func groupBy<Key : Hashable, Item>(_ fn:(Item) -> Key, matchWith:((Key,Key) -> Bool)?) -> [Group<Key,Item>] {
		return self.groupBy(fn, matchWith: matchWith, valueAs: nil)
	}

	public func groupBy<Key : Hashable, Item>(_ fn: (Item) -> Key,
	                    matchWith: ((Key,Key) -> Bool)?,
	                    valueAs:   ((Item) -> Item)?) -> [Group<Key,Item>]
	{
		var map = Dictionary<Key, Group<Key,Item>>()
		for x in self {
			var element = x as! Item
			let val = fn(element)

			var key = val as Key

			if (matchWith != nil) {
				for k in map.keys {
					if matchWith!(val, k) {
						key = k
						break
					}
				}
			}

			if let valueAs = valueAs {
				element = valueAs(element)
			}

			var group: Group<Key,Item>
			if let item = map[key] {
				group = item
			} else {
				group = Group<Key,Item>(key:key)
			}

			group.append(item: element)
			map[key] = group //always copy back struct
		}

		return map.values.map { $0 as Group<Key,Item> }
	}

	public struct Group<Key,Item> {

		public let key: Key
		public var items = [Item]()

		public init(key:Key) {
			self.key = key
		}

		mutating func append(item: Item) {
			items.append(item)
		}

		func generate() -> IndexingIterator<[Item]> {
			return items.makeIterator()
		}
	}

}

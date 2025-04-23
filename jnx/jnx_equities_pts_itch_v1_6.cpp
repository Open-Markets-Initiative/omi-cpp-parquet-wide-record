#include <chrono>
#include <cstring>
#include <ctime>
#include <iostream>
#include <utility>

#include "pcap.h"
#include "netinet/if_ether.h"
#include "netinet/ip.h"
#include "netinet/udp.h"
#include "arrow/io/file.h"
#include "parquet/exception.h"
#include "parquet/stream_reader.h"
#include "parquet/stream_writer.h"

namespace jnx::itch {

///////////////////////////////////////////////////////////////////////
// pcap types
///////////////////////////////////////////////////////////////////////

// pcap frame index
struct pcap_index {

    static constexpr auto name = "pcap_index";
    static constexpr auto repetition = parquet::Repetition::REQUIRED;
    static constexpr auto parquet_type = parquet::Type::INT64;
    static constexpr auto converted_type = parquet::ConvertedType::UINT_64;

    pcap_index() = default;

    void set(const std::uint64_t value) {
        data = value;
    }

    void increment() {
        data++;
    }

    static auto node() {
        return parquet::schema::PrimitiveNode::Make(name, repetition, parquet_type, converted_type);
    }

    std::uint64_t data;
};

inline auto& operator<<(std::ostream& stream, const pcap_index& field) {
    return stream << field.data;
}

inline auto& operator<<(parquet::StreamWriter& stream, const pcap_index& field) {
    return stream << field.data;
}

inline auto& operator>>(parquet::StreamReader& stream, pcap_index& field) {
    return stream >> field.data;
}

// pcap timestamp
struct pcap_timestamp {

    static constexpr auto name = "timestamp";
    static constexpr auto repetition = parquet::Repetition::REQUIRED;
    static constexpr auto parquet_type = parquet::Type::INT64;
    static constexpr auto converted_type = parquet::ConvertedType::TIMESTAMP_MICROS;

    pcap_timestamp() = default;

    void set(const std::chrono::microseconds value) {
        data = value;
    }

    void set(const pcap_pkthdr *pkthdr) {
        const auto duration = std::chrono::seconds{pkthdr->ts.tv_sec} + std::chrono::microseconds{pkthdr->ts.tv_usec};
        data = duration_cast<std::chrono::microseconds>(duration);
    }

    static auto node() {
        return parquet::schema::PrimitiveNode::Make(name, repetition, parquet_type, converted_type);
    }

    std::chrono::microseconds data;
};

inline auto& operator<<(std::ostream& stream, const pcap_timestamp& field) {
    const auto timestamp = std::chrono::duration_cast<std::chrono::seconds>(field.data).count();
    return stream << std::put_time(std::gmtime(&timestamp), "%Y-%m-%d %X");
}

inline auto& operator<<(parquet::StreamWriter& stream, const pcap_timestamp& field) {
    return stream << field.data;
}

inline auto& operator>>(parquet::StreamReader& stream, pcap_timestamp& field) {
    std::chrono::microseconds microseconds;
    stream >> microseconds;
    field.set(microseconds);

    return stream;
}

///////////////////////////////////////////////////////////////////////
// itch header types
///////////////////////////////////////////////////////////////////////

// Identity of the multicast session
struct session {

    static constexpr auto name = "session";
    static constexpr auto repetition = parquet::Repetition::REQUIRED;
    static constexpr auto parquet_type = parquet::Type::BYTE_ARRAY;
    static constexpr auto converted_type = parquet::ConvertedType::UTF8;
    static constexpr std::uint32_t size = 10;

    session() = default;

    void set(u_char** current) {
        data.assign(reinterpret_cast<char *>(*current), size);
        *current += size;
    }

    static auto node() {
        return parquet::schema::PrimitiveNode::Make(name, repetition, parquet_type, converted_type);
    }

    std::string data;
};

inline auto& operator<<(std::ostream& stream, const session& field) {
    return stream << field.data;
}

inline auto& operator<<(parquet::StreamWriter& stream, const session& field) {
    return stream << field.data;
}

inline auto& operator>>(parquet::StreamReader& stream, session& field) {
    return stream >> field.data;
}

// message sequence
struct message_sequence {

    static constexpr auto name = "message_sequence";
    static constexpr auto repetition = parquet::Repetition::REQUIRED;
    static constexpr auto parquet_type = parquet::Type::INT64;
    static constexpr auto converted_type = parquet::ConvertedType::UINT_64;
    static constexpr std::uint32_t size = 8;

    message_sequence() = default;

    void set(u_char** current) {
        data = htobe64(*reinterpret_cast<std::uint64_t*>(*current));
        *current += size;
    }

    void increment() {
        data++;
    }

    static auto node() {
        return parquet::schema::PrimitiveNode::Make(name, repetition, parquet_type, converted_type);
    }

    std::uint64_t data;
};

inline auto& operator<<(std::ostream& stream, const message_sequence& field) {
    return stream << field.data;
}

inline auto& operator<<(parquet::StreamWriter& stream, const message_sequence& field) {
    return stream << field.data;
}

inline auto& operator>>(parquet::StreamReader& stream, message_sequence& field) {
    return stream >> field.data;
}

// message index (count)
struct message_index {

    static constexpr auto name = "message_index";
    static constexpr auto repetition = parquet::Repetition::REQUIRED;
    static constexpr auto parquet_type = parquet::Type::INT32;
    static constexpr auto converted_type = parquet::ConvertedType::UINT_16;
    static constexpr std::uint32_t size = 2;

    message_index() = default;

    void set(u_char** current) {
        count = htobe16(*reinterpret_cast<uint16_t*>(*current));
        data = 0;
        *current += size;
    }

    bool increment() {
        data++;
        return data <= count;
    }

    static auto node() {
        return parquet::schema::PrimitiveNode::Make(name, repetition, parquet_type, converted_type);
    }

    std::uint16_t count = 0;
    std::uint16_t data = 0;
};

inline auto& operator<<(std::ostream& stream, const message_index& field) {
    return stream << field.data;
}

inline auto& operator<<(parquet::StreamWriter& stream, const message_index& field) {
    return stream << field.data;
}

inline auto& operator>>(parquet::StreamReader& stream, message_index& field) {
    return stream >> field.data;
}

// message length
struct message_length {

    static constexpr auto name = "message_length";
    static constexpr std::uint32_t size = 2;

    message_length() = default;

    void set(u_char** current, u_char** message) {
        data = htobe16(*reinterpret_cast<std::uint16_t*>(*current));
        *current += size;
        *message = *current;
        *current += data;
    }

    std::uint16_t data;
};

// message type
struct message_type {

    static constexpr auto name = "message_type";
    static constexpr auto repetition = parquet::Repetition::REQUIRED;
    static constexpr auto parquet_type = parquet::Type::INT32;
    static constexpr auto converted_type = parquet::ConvertedType::UINT_8;
    static constexpr std::uint32_t size = 1;

    message_type() = default;

    void set(u_char** current) {
        data = *reinterpret_cast<char*>(*current);
        *current += size;
    }

    static auto node() {
        return parquet::schema::PrimitiveNode::Make(name, repetition, parquet_type, converted_type);
    }

    char data;
};

inline auto& operator<<(std::ostream& stream, const message_type& field) {
    return stream << field.data;
}

inline auto& operator<<(parquet::StreamWriter& stream, const message_type& field) {
    return stream << static_cast<uint8_t>(field.data);
}

inline auto& operator>>(parquet::StreamReader& stream, message_type& field) {
    uint8_t data = 0;
    stream >> data;
    field.data = static_cast<char>(data);
    return stream;
}

///////////////////////////////////////////////////////////////////////
// itch message types
///////////////////////////////////////////////////////////////////////

// Reserved.
struct attribution {

    static constexpr auto name = "attribution";
    static constexpr auto repetition = parquet::Repetition::OPTIONAL;
    static constexpr auto parquet_type = parquet::Type::BYTE_ARRAY;
    static constexpr auto converted_type = parquet::ConvertedType::UTF8;
    static constexpr std::uint32_t size = 4;

    attribution() = default;

    void reset() {
        data.reset();
    }

    void set(u_char** current) {
        std::uint32_t index = 0;
        for (; index < size; ++index) {
            if (*(*current + index) == ' ') { break; }
        }
        data = std::string_view(reinterpret_cast<char *>(*current), index);
        *current += size;
    }

    static auto node() {
        return parquet::schema::PrimitiveNode::Make(name, repetition, parquet_type, converted_type);
    }

    std::optional<std::string> data;
};

inline auto& operator<<(std::ostream& stream, const attribution& field) {
    if (field.data) {
        return stream << field.data.value();
    }

    return stream;
}

inline auto& operator<<(parquet::StreamWriter& stream, const attribution& field) {
    return stream << field.data;
}

inline auto& operator>>(parquet::StreamReader& stream, attribution& field) {
    return stream >> field.data;
}

// Side of the order.
struct buy_sell_indicator {

    static constexpr auto name = "buy_sell_indicator";
    static constexpr auto repetition = parquet::Repetition::OPTIONAL;
    static constexpr auto parquet_type = parquet::Type::INT32;
    static constexpr auto converted_type = parquet::ConvertedType::UINT_8;
    static constexpr std::uint32_t size = 1;

    buy_sell_indicator() = default;

    void set(u_char** current) {
        data = *reinterpret_cast<char*>(*current);
        *current += size;
    }

    void reset() {
        data.reset();
    }

    static auto node() {
        return parquet::schema::PrimitiveNode::Make(name, repetition, parquet_type, converted_type);
    }

    std::optional<std::uint8_t> data;
};

inline auto& operator<<(std::ostream& stream, const buy_sell_indicator& field) {
    if (field.data) {
        return stream << static_cast<char>(field.data.value());
    }

    return stream;
}

inline auto& operator<<(parquet::StreamWriter& stream, const buy_sell_indicator& field) {
    return stream << field.data;
}

inline auto& operator>>(parquet::StreamReader& stream, buy_sell_indicator& field) {
    return stream >> field.data;
}

// Number of shares executed.
struct executed_quantity {

    static constexpr auto name = "executed_quantity";
    static constexpr auto repetition = parquet::Repetition::OPTIONAL;
    static constexpr auto type = parquet::Type::INT32;
    static constexpr auto converted_type = parquet::ConvertedType::UINT_32;
    static constexpr std::uint32_t size = 4;

    executed_quantity() = default;

    void set(u_char** current) {
        data = htobe32(*reinterpret_cast<std::uint32_t*>(*current));
        *current += size;
    }

    void reset() {
        data.reset();
    }

    static auto node() {
        return parquet::schema::PrimitiveNode::Make(name, repetition, type, converted_type);
    }

    std::optional<std::uint32_t> data;
};

inline auto& operator<<(std::ostream& stream, const executed_quantity& field) {
    if (field.data) {
        return stream << field.data.value();
    }

    return stream;
}

inline auto& operator<<(parquet::StreamWriter& stream, const executed_quantity& field) {
    return stream << field.data;
}

inline auto& operator>>(parquet::StreamReader& stream, executed_quantity& field) {
    return stream >> field.data;
}

// Orderbook group identifier.
struct group {

    static constexpr auto name = "group";
    static constexpr auto repetition = parquet::Repetition::OPTIONAL;
    static constexpr auto parquet_type = parquet::Type::BYTE_ARRAY;
    static constexpr auto converted_type = parquet::ConvertedType::UTF8;
    static constexpr std::uint32_t size = 4;

    group() = default;

    void reset() {
        data.reset();
    }

    void set(u_char** current) {
        std::uint32_t index = 0;
        for (; index < size; ++index) {
            if (*(*current + index) == ' ') { break; }
        }
        data = std::string_view(reinterpret_cast<char *>(*current), index);
        *current += size;
    }

    static auto node() {
        return parquet::schema::PrimitiveNode::Make(name, repetition, parquet_type, converted_type);
    }

    std::optional<std::string> data;
};

inline auto& operator<<(std::ostream& stream, const group& field) {
    if (field.data) {
        return stream << field.data.value();
    }

    return stream;
}

inline auto& operator<<(parquet::StreamWriter& stream, const group& field) {
    return stream << field.data;
}

inline auto& operator>>(parquet::StreamReader& stream, group& field) {
    return stream >> field.data;
}

// Minimum tradable price.
struct lower_price_limit {

    static constexpr auto name = "lower_price_limit";
    static constexpr auto repetition = parquet::Repetition::OPTIONAL;
    static constexpr auto type = parquet::Type::INT32;
    static constexpr auto converted_type = parquet::ConvertedType::UINT_32;
    static constexpr std::uint32_t size = 4;

    lower_price_limit() = default;

    void set(u_char** current) {
        data = htobe32(*reinterpret_cast<std::uint32_t*>(*current));
        *current += size;
    }

    void reset() {
        data.reset();
    }

    static auto node() {
        return parquet::schema::PrimitiveNode::Make(name, repetition, type, converted_type);
    }

    std::optional<std::uint32_t> data;
};

inline auto& operator<<(std::ostream& stream, const lower_price_limit& field) {
    if (field.data) {
        return stream << field.data.value();
    }

    return stream;
}

inline auto& operator<<(parquet::StreamWriter& stream, const lower_price_limit& field) {
    return stream << field.data;
}

inline auto& operator>>(parquet::StreamReader& stream, lower_price_limit& field) {
    return stream >> field.data;
}

// Reference number of the match.
struct match_number {

    static constexpr auto name = "match_number";
    static constexpr auto repetition = parquet::Repetition::OPTIONAL;
    static constexpr auto type = parquet::Type::INT64;
    static constexpr auto converted_type = parquet::ConvertedType::UINT_64;
    static constexpr std::uint32_t size = 8;

    match_number() = default;

    void set(u_char** current) {
        data = htobe64(*reinterpret_cast<std::uint64_t*>(*current));
        *current += size;
    }

    void reset() {
        data.reset();
    }

    static auto node() {
        return parquet::schema::PrimitiveNode::Make(name, repetition, type, converted_type);
    }

    std::optional<std::uint64_t> data;
};

inline auto& operator<<(std::ostream& stream, const match_number& field) {
    if (field.data) {
        return stream << field.data.value();
    }

    return stream;
}

inline auto& operator<<(parquet::StreamWriter& stream, const match_number& field) {
    return stream << field.data;
}

inline auto& operator>>(parquet::StreamReader& stream, match_number& field) {
    return stream >> field.data;
}

// Reference number of the replaced order.
struct new_order_number {

    static constexpr auto name = "new_order_number";
    static constexpr auto repetition = parquet::Repetition::OPTIONAL;
    static constexpr auto type = parquet::Type::INT64;
    static constexpr auto converted_type = parquet::ConvertedType::UINT_64;
    static constexpr std::uint32_t size = 8;

    new_order_number() = default;

    void set(u_char** current) {
        data = htobe64(*reinterpret_cast<std::uint64_t*>(*current));
        *current += size;
    }

    void reset() {
        data.reset();
    }

    static auto node() {
        return parquet::schema::PrimitiveNode::Make(name, repetition, type, converted_type);
    }

    std::optional<std::uint64_t> data;
};

inline auto& operator<<(std::ostream& stream, const new_order_number& field) {
    if (field.data) {
        return stream << field.data.value();
    }

    return stream;
}

inline auto& operator<<(parquet::StreamWriter& stream, const new_order_number& field) {
    return stream << field.data;
}

inline auto& operator>>(parquet::StreamReader& stream, new_order_number& field) {
    return stream >> field.data;
}

// Reference number of the accepted order.
struct order_number {

    static constexpr auto name = "order_number";
    static constexpr auto repetition = parquet::Repetition::OPTIONAL;
    static constexpr auto type = parquet::Type::INT64;
    static constexpr auto converted_type = parquet::ConvertedType::UINT_64;
    static constexpr std::uint32_t size = 8;

    order_number() = default;

    void set(u_char** current) {
        data = htobe64(*reinterpret_cast<std::uint64_t*>(*current));
        *current += size;
    }

    void reset() {
        data.reset();
    }

    static auto node() {
        return parquet::schema::PrimitiveNode::Make(name, repetition, type, converted_type);
    }

    std::optional<std::uint64_t> data;
};

inline auto& operator<<(std::ostream& stream, const order_number& field) {
    if (field.data) {
        return stream << field.data.value();
    }

    return stream;
}

inline auto& operator<<(parquet::StreamWriter& stream, const order_number& field) {
    return stream << field.data;
}

inline auto& operator>>(parquet::StreamReader& stream, order_number& field) {
    return stream >> field.data;
}

// Type of the order.
struct order_type {

    static constexpr auto name = "order_type";
    static constexpr auto repetition = parquet::Repetition::OPTIONAL;
    static constexpr auto parquet_type = parquet::Type::INT32;
    static constexpr auto converted_type = parquet::ConvertedType::UINT_8;
    static constexpr std::uint32_t size = 1;

    order_type() = default;

    void set(u_char** current) {
        data = *reinterpret_cast<char*>(*current);
        *current += size;
    }

    void reset() {
        data.reset();
    }

    static auto node() {
        return parquet::schema::PrimitiveNode::Make(name, repetition, parquet_type, converted_type);
    }

    std::optional<std::uint8_t> data;
};

inline auto& operator<<(std::ostream& stream, const order_type& field) {
    if (field.data) {
        return stream << static_cast<char>(field.data.value());
    }

    return stream;
}

inline auto& operator<<(parquet::StreamWriter& stream, const order_type& field) {
    return stream << field.data;
}

inline auto& operator>>(parquet::StreamReader& stream, order_type& field) {
    return stream >> field.data;
}

// International Securities Identification Number (ISIN).
struct orderbook_code {

    static constexpr auto name = "orderbook_code";
    static constexpr auto repetition = parquet::Repetition::OPTIONAL;
    static constexpr auto parquet_type = parquet::Type::BYTE_ARRAY;
    static constexpr auto converted_type = parquet::ConvertedType::UTF8;
    static constexpr std::uint32_t size = 12;

    orderbook_code() = default;

    void reset() {
        data.reset();
    }

    void set(u_char** current) {
        std::uint32_t index = 0;
        for (; index < size; ++index) {
            if (*(*current + index) == ' ') { break; }
        }
        data = std::string_view(reinterpret_cast<char *>(*current), index);
        *current += size;
    }

    static auto node() {
        return parquet::schema::PrimitiveNode::Make(name, repetition, parquet_type, converted_type);
    }

    std::optional<std::string> data;
};

inline auto& operator<<(std::ostream& stream, const orderbook_code& field) {
    if (field.data) {
        return stream << field.data.value();
    }

    return stream;
}

inline auto& operator<<(parquet::StreamWriter& stream, const orderbook_code& field) {
    return stream << field.data;
}

inline auto& operator>>(parquet::StreamReader& stream, orderbook_code& field) {
    return stream >> field.data;
}

// 4 digit Quick code.
struct orderbook_id {

    static constexpr auto name = "orderbook_id";
    static constexpr auto repetition = parquet::Repetition::OPTIONAL;
    static constexpr auto type = parquet::Type::INT32;
    static constexpr auto converted_type = parquet::ConvertedType::UINT_32;
    static constexpr std::uint32_t size = 4;

    orderbook_id() = default;

    void set(u_char** current) {
        data = htobe32(*reinterpret_cast<std::uint32_t*>(*current));
        *current += size;
    }

    void reset() {
        data.reset();
    }

    static auto node() {
        return parquet::schema::PrimitiveNode::Make(name, repetition, type, converted_type);
    }

    std::optional<std::uint32_t> data;
};

inline auto& operator<<(std::ostream& stream, const orderbook_id& field) {
    if (field.data) {
        return stream << field.data.value();
    }

    return stream;
}

inline auto& operator<<(parquet::StreamWriter& stream, const orderbook_id& field) {
    return stream << field.data;
}

inline auto& operator>>(parquet::StreamReader& stream, orderbook_id& field) {
    return stream >> field.data;
}

// Reference number of the original order.
struct original_order_number {

    static constexpr auto name = "original_order_number";
    static constexpr auto repetition = parquet::Repetition::OPTIONAL;
    static constexpr auto type = parquet::Type::INT64;
    static constexpr auto converted_type = parquet::ConvertedType::UINT_64;
    static constexpr std::uint32_t size = 8;

    original_order_number() = default;

    void set(u_char** current) {
        data = htobe64(*reinterpret_cast<std::uint64_t*>(*current));
        *current += size;
    }

    void reset() {
        data.reset();
    }

    static auto node() {
        return parquet::schema::PrimitiveNode::Make(name, repetition, type, converted_type);
    }

    std::optional<std::uint64_t> data;
};

inline auto& operator<<(std::ostream& stream, const original_order_number& field) {
    if (field.data) {
        return stream << field.data.value();
    }

    return stream;
}

inline auto& operator<<(parquet::StreamWriter& stream, const original_order_number& field) {
    return stream << field.data;
}

inline auto& operator>>(parquet::StreamReader& stream, original_order_number& field) {
    return stream >> field.data;
}

// Price of the order.
struct price {

    static constexpr auto name = "price";
    static constexpr auto repetition = parquet::Repetition::OPTIONAL;
    static constexpr auto type = parquet::Type::INT32;
    static constexpr auto converted_type = parquet::ConvertedType::UINT_32;
    static constexpr std::uint32_t size = 4;

    price() = default;

    void set(u_char** current) {
        data = htobe32(*reinterpret_cast<std::uint32_t*>(*current));
        *current += size;
    }

    void reset() {
        data.reset();
    }

    static auto node() {
        return parquet::schema::PrimitiveNode::Make(name, repetition, type, converted_type);
    }

    std::optional<std::uint32_t> data;
};

inline auto& operator<<(std::ostream& stream, const price& field) {
    if (field.data) {
        return stream << field.data.value();
    }

    return stream;
}

inline auto& operator<<(parquet::StreamWriter& stream, const price& field) {
    return stream << field.data;
}

inline auto& operator>>(parquet::StreamReader& stream, price& field) {
    return stream >> field.data;
}

// Number of decimal places in price fields.
struct price_decimals {

    static constexpr auto name = "price_decimals";
    static constexpr auto repetition = parquet::Repetition::OPTIONAL;
    static constexpr auto type = parquet::Type::INT32;
    static constexpr auto converted_type = parquet::ConvertedType::UINT_32;
    static constexpr std::uint32_t size = 4;

    price_decimals() = default;

    void set(u_char** current) {
        data = htobe32(*reinterpret_cast<std::uint32_t*>(*current));
        *current += size;
    }

    void reset() {
        data.reset();
    }

    static auto node() {
        return parquet::schema::PrimitiveNode::Make(name, repetition, type, converted_type);
    }

    std::optional<std::uint32_t> data;
};

inline auto& operator<<(std::ostream& stream, const price_decimals& field) {
    if (field.data) {
        return stream << field.data.value();
    }

    return stream;
}

inline auto& operator<<(parquet::StreamWriter& stream, const price_decimals& field) {
    return stream << field.data;
}

inline auto& operator>>(parquet::StreamReader& stream, price_decimals& field) {
    return stream >> field.data;
}

// Start of price range for this price tick size.
struct price_start {

    static constexpr auto name = "price_start";
    static constexpr auto repetition = parquet::Repetition::OPTIONAL;
    static constexpr auto type = parquet::Type::INT32;
    static constexpr auto converted_type = parquet::ConvertedType::UINT_32;
    static constexpr std::uint32_t size = 4;

    price_start() = default;

    void set(u_char** current) {
        data = htobe32(*reinterpret_cast<std::uint32_t*>(*current));
        *current += size;
    }

    void reset() {
        data.reset();
    }

    static auto node() {
        return parquet::schema::PrimitiveNode::Make(name, repetition, type, converted_type);
    }

    std::optional<std::uint32_t> data;
};

inline auto& operator<<(std::ostream& stream, const price_start& field) {
    if (field.data) {
        return stream << field.data.value();
    }

    return stream;
}

inline auto& operator<<(parquet::StreamWriter& stream, const price_start& field) {
    return stream << field.data;
}

inline auto& operator>>(parquet::StreamReader& stream, price_start& field) {
    return stream >> field.data;
}

// Price tick size.
struct price_tick_size {

    static constexpr auto name = "price_tick_size";
    static constexpr auto repetition = parquet::Repetition::OPTIONAL;
    static constexpr auto type = parquet::Type::INT32;
    static constexpr auto converted_type = parquet::ConvertedType::UINT_32;
    static constexpr std::uint32_t size = 4;

    price_tick_size() = default;

    void set(u_char** current) {
        data = htobe32(*reinterpret_cast<std::uint32_t*>(*current));
        *current += size;
    }

    void reset() {
        data.reset();
    }

    static auto node() {
        return parquet::schema::PrimitiveNode::Make(name, repetition, type, converted_type);
    }

    std::optional<std::uint32_t> data;
};

inline auto& operator<<(std::ostream& stream, const price_tick_size& field) {
    if (field.data) {
        return stream << field.data.value();
    }

    return stream;
}

inline auto& operator<<(parquet::StreamWriter& stream, const price_tick_size& field) {
    return stream << field.data;
}

inline auto& operator>>(parquet::StreamReader& stream, price_tick_size& field) {
    return stream >> field.data;
}

// Price tick size table identifier.
struct price_tick_size_table_id {

    static constexpr auto name = "price_tick_size_table_id";
    static constexpr auto repetition = parquet::Repetition::OPTIONAL;
    static constexpr auto type = parquet::Type::INT32;
    static constexpr auto converted_type = parquet::ConvertedType::UINT_32;
    static constexpr std::uint32_t size = 4;

    price_tick_size_table_id() = default;

    void set(u_char** current) {
        data = htobe32(*reinterpret_cast<std::uint32_t*>(*current));
        *current += size;
    }

    void reset() {
        data.reset();
    }

    static auto node() {
        return parquet::schema::PrimitiveNode::Make(name, repetition, type, converted_type);
    }

    std::optional<std::uint32_t> data;
};

inline auto& operator<<(std::ostream& stream, const price_tick_size_table_id& field) {
    if (field.data) {
        return stream << field.data.value();
    }

    return stream;
}

inline auto& operator<<(parquet::StreamWriter& stream, const price_tick_size_table_id& field) {
    return stream << field.data;
}

inline auto& operator>>(parquet::StreamReader& stream, price_tick_size_table_id& field) {
    return stream >> field.data;
}

// Total number of shares added to the book.
struct quantity {

    static constexpr auto name = "quantity";
    static constexpr auto repetition = parquet::Repetition::OPTIONAL;
    static constexpr auto type = parquet::Type::INT32;
    static constexpr auto converted_type = parquet::ConvertedType::UINT_32;
    static constexpr std::uint32_t size = 4;

    quantity() = default;

    void set(u_char** current) {
        data = htobe32(*reinterpret_cast<std::uint32_t*>(*current));
        *current += size;
    }

    void reset() {
        data.reset();
    }

    static auto node() {
        return parquet::schema::PrimitiveNode::Make(name, repetition, type, converted_type);
    }

    std::optional<std::uint32_t> data;
};

inline auto& operator<<(std::ostream& stream, const quantity& field) {
    if (field.data) {
        return stream << field.data.value();
    }

    return stream;
}

inline auto& operator<<(parquet::StreamWriter& stream, const quantity& field) {
    return stream << field.data;
}

inline auto& operator>>(parquet::StreamReader& stream, quantity& field) {
    return stream >> field.data;
}

// Number of shares that represent a round lot.
struct round_lot_size {

    static constexpr auto name = "round_lot_size";
    static constexpr auto repetition = parquet::Repetition::OPTIONAL;
    static constexpr auto type = parquet::Type::INT32;
    static constexpr auto converted_type = parquet::ConvertedType::UINT_32;
    static constexpr std::uint32_t size = 4;

    round_lot_size() = default;

    void set(u_char** current) {
        data = htobe32(*reinterpret_cast<std::uint32_t*>(*current));
        *current += size;
    }

    void reset() {
        data.reset();
    }

    static auto node() {
        return parquet::schema::PrimitiveNode::Make(name, repetition, type, converted_type);
    }

    std::optional<std::uint32_t> data;
};

inline auto& operator<<(std::ostream& stream, const round_lot_size& field) {
    if (field.data) {
        return stream << field.data.value();
    }

    return stream;
}

inline auto& operator<<(parquet::StreamWriter& stream, const round_lot_size& field) {
    return stream << field.data;
}

inline auto& operator>>(parquet::StreamReader& stream, round_lot_size& field) {
    return stream >> field.data;
}

// Current short selling price restriction state.
struct short_selling_state {

    static constexpr auto name = "short_selling_state";
    static constexpr auto repetition = parquet::Repetition::OPTIONAL;
    static constexpr auto parquet_type = parquet::Type::INT32;
    static constexpr auto converted_type = parquet::ConvertedType::UINT_8;
    static constexpr std::uint32_t size = 1;

    short_selling_state() = default;

    void set(u_char** current) {
        data = *reinterpret_cast<char*>(*current);
        *current += size;
    }

    void reset() {
        data.reset();
    }

    static auto node() {
        return parquet::schema::PrimitiveNode::Make(name, repetition, parquet_type, converted_type);
    }

    std::optional<std::uint8_t> data;
};

inline auto& operator<<(std::ostream& stream, const short_selling_state& field) {
    if (field.data) {
        return stream << static_cast<char>(field.data.value());
    }

    return stream;
}

inline auto& operator<<(parquet::StreamWriter& stream, const short_selling_state& field) {
    return stream << field.data;
}

inline auto& operator>>(parquet::StreamReader& stream, short_selling_state& field) {
    return stream >> field.data;
}

// Refer to the System Events table below.
struct system_event {

    static constexpr auto name = "system_event";
    static constexpr auto repetition = parquet::Repetition::OPTIONAL;
    static constexpr auto parquet_type = parquet::Type::INT32;
    static constexpr auto converted_type = parquet::ConvertedType::UINT_8;
    static constexpr std::uint32_t size = 1;

    system_event() = default;

    void set(u_char** current) {
        data = *reinterpret_cast<char*>(*current);
        *current += size;
    }

    void reset() {
        data.reset();
    }

    static auto node() {
        return parquet::schema::PrimitiveNode::Make(name, repetition, parquet_type, converted_type);
    }

    std::optional<std::uint8_t> data;
};

inline auto& operator<<(std::ostream& stream, const system_event& field) {
    if (field.data) {
        return stream << static_cast<char>(field.data.value());
    }

    return stream;
}

inline auto& operator<<(parquet::StreamWriter& stream, const system_event& field) {
    return stream << field.data;
}

inline auto& operator>>(parquet::StreamReader& stream, system_event& field) {
    return stream >> field.data;
}

// Number of nanoseconds since last Timestamp – Seconds Message.
struct timestamp_nanoseconds {

    static constexpr auto name = "timestamp_nanoseconds";
    static constexpr auto repetition = parquet::Repetition::OPTIONAL;
    static constexpr auto type = parquet::Type::INT32;
    static constexpr auto converted_type = parquet::ConvertedType::UINT_32;
    static constexpr std::uint32_t size = 4;

    timestamp_nanoseconds() = default;

    void set(u_char** current) {
        data = htobe32(*reinterpret_cast<std::uint32_t*>(*current));
        *current += size;
    }

    void reset() {
        data.reset();
    }

    static auto node() {
        return parquet::schema::PrimitiveNode::Make(name, repetition, type, converted_type);
    }

    std::optional<std::uint32_t> data;
};

inline auto& operator<<(std::ostream& stream, const timestamp_nanoseconds& field) {
    if (field.data) {
        return stream << field.data.value();
    }

    return stream;
}

inline auto& operator<<(parquet::StreamWriter& stream, const timestamp_nanoseconds& field) {
    return stream << field.data;
}

inline auto& operator>>(parquet::StreamReader& stream, timestamp_nanoseconds& field) {
    return stream >> field.data;
}

// Number of seconds since midnight of the day that the trading session started.
struct timestamp_seconds {

    static constexpr auto name = "timestamp_seconds";
    static constexpr auto repetition = parquet::Repetition::OPTIONAL;
    static constexpr auto type = parquet::Type::INT32;
    static constexpr auto converted_type = parquet::ConvertedType::UINT_32;
    static constexpr std::uint32_t size = 4;

    timestamp_seconds() = default;

    void set(u_char** current) {
        data = htobe32(*reinterpret_cast<std::uint32_t*>(*current));
        *current += size;
    }

    void reset() {
        data.reset();
    }

    static auto node() {
        return parquet::schema::PrimitiveNode::Make(name, repetition, type, converted_type);
    }

    std::optional<std::uint32_t> data;
};

inline auto& operator<<(std::ostream& stream, const timestamp_seconds& field) {
    if (field.data) {
        return stream << field.data.value();
    }

    return stream;
}

inline auto& operator<<(parquet::StreamWriter& stream, const timestamp_seconds& field) {
    return stream << field.data;
}

inline auto& operator>>(parquet::StreamReader& stream, timestamp_seconds& field) {
    return stream >> field.data;
}

// Current trading state.
struct trading_state {

    static constexpr auto name = "trading_state";
    static constexpr auto repetition = parquet::Repetition::OPTIONAL;
    static constexpr auto parquet_type = parquet::Type::INT32;
    static constexpr auto converted_type = parquet::ConvertedType::UINT_8;
    static constexpr std::uint32_t size = 1;

    trading_state() = default;

    void set(u_char** current) {
        data = *reinterpret_cast<char*>(*current);
        *current += size;
    }

    void reset() {
        data.reset();
    }

    static auto node() {
        return parquet::schema::PrimitiveNode::Make(name, repetition, parquet_type, converted_type);
    }

    std::optional<std::uint8_t> data;
};

inline auto& operator<<(std::ostream& stream, const trading_state& field) {
    if (field.data) {
        return stream << static_cast<char>(field.data.value());
    }

    return stream;
}

inline auto& operator<<(parquet::StreamWriter& stream, const trading_state& field) {
    return stream << field.data;
}

inline auto& operator>>(parquet::StreamReader& stream, trading_state& field) {
    return stream >> field.data;
}

// Maximum tradable price.
struct upper_price_limit {

    static constexpr auto name = "upper_price_limit";
    static constexpr auto repetition = parquet::Repetition::OPTIONAL;
    static constexpr auto type = parquet::Type::INT32;
    static constexpr auto converted_type = parquet::ConvertedType::UINT_32;
    static constexpr std::uint32_t size = 4;

    upper_price_limit() = default;

    void set(u_char** current) {
        data = htobe32(*reinterpret_cast<std::uint32_t*>(*current));
        *current += size;
    }

    void reset() {
        data.reset();
    }

    static auto node() {
        return parquet::schema::PrimitiveNode::Make(name, repetition, type, converted_type);
    }

    std::optional<std::uint32_t> data;
};

inline auto& operator<<(std::ostream& stream, const upper_price_limit& field) {
    if (field.data) {
        return stream << field.data.value();
    }

    return stream;
}

inline auto& operator<<(parquet::StreamWriter& stream, const upper_price_limit& field) {
    return stream << field.data;
}

inline auto& operator>>(parquet::StreamReader& stream, upper_price_limit& field) {
    return stream >> field.data;
}

///////////////////////////////////////////////////////////////////////
// itch record
///////////////////////////////////////////////////////////////////////

// Note
struct record {

    // pcap fields
    jnx::itch::pcap_index pcap_index;
    jnx::itch::pcap_timestamp pcap_timestamp;

    // header fields
    jnx::itch::session session;
    jnx::itch::message_sequence message_sequence;
    jnx::itch::message_index message_index;
    jnx::itch::message_length message_length;
    jnx::itch::message_type message_type;

    // message fields
    jnx::itch::attribution attribution;
    jnx::itch::buy_sell_indicator buy_sell_indicator;
    jnx::itch::executed_quantity executed_quantity;
    jnx::itch::group group;
    jnx::itch::lower_price_limit lower_price_limit;
    jnx::itch::match_number match_number;
    jnx::itch::new_order_number new_order_number;
    jnx::itch::order_number order_number;
    jnx::itch::order_type order_type;
    jnx::itch::orderbook_code orderbook_code;
    jnx::itch::orderbook_id orderbook_id;
    jnx::itch::original_order_number original_order_number;
    jnx::itch::price price;
    jnx::itch::price_decimals price_decimals;
    jnx::itch::price_start price_start;
    jnx::itch::price_tick_size price_tick_size;
    jnx::itch::price_tick_size_table_id price_tick_size_table_id;
    jnx::itch::quantity quantity;
    jnx::itch::round_lot_size round_lot_size;
    jnx::itch::short_selling_state short_selling_state;
    jnx::itch::system_event system_event;
    jnx::itch::timestamp_nanoseconds timestamp_nanoseconds;
    jnx::itch::timestamp_seconds timestamp_seconds;
    jnx::itch::trading_state trading_state;
    jnx::itch::upper_price_limit upper_price_limit;

    record() = default;

    // reset composite message record
    void reset() {
        attribution.reset();
        buy_sell_indicator.reset();
        executed_quantity.reset();
        group.reset();
        lower_price_limit.reset();
        match_number.reset();
        new_order_number.reset();
        order_number.reset();
        order_type.reset();
        orderbook_code.reset();
        orderbook_id.reset();
        original_order_number.reset();
        price.reset();
        price_decimals.reset();
        price_start.reset();
        price_tick_size.reset();
        price_tick_size_table_id.reset();
        quantity.reset();
        round_lot_size.reset();
        short_selling_state.reset();
        system_event.reset();
        timestamp_nanoseconds.reset();
        timestamp_seconds.reset();
        trading_state.reset();
        upper_price_limit.reset();
    }

    // parquet schema nodes
    static auto nodes() {
        return parquet::schema::NodeVector {
            jnx::itch::pcap_index::node(),
            jnx::itch::pcap_timestamp::node(),
            jnx::itch::session::node(),
            jnx::itch::message_sequence::node(),
            jnx::itch::message_index::node(),
            jnx::itch::message_type::node(),
            jnx::itch::attribution::node(),
            jnx::itch::buy_sell_indicator::node(),
            jnx::itch::executed_quantity::node(),
            jnx::itch::group::node(),
            jnx::itch::lower_price_limit::node(),
            jnx::itch::match_number::node(),
            jnx::itch::new_order_number::node(),
            jnx::itch::order_number::node(),
            jnx::itch::order_type::node(),
            jnx::itch::orderbook_code::node(),
            jnx::itch::orderbook_id::node(),
            jnx::itch::original_order_number::node(),
            jnx::itch::price::node(),
            jnx::itch::price_decimals::node(),
            jnx::itch::price_start::node(),
            jnx::itch::price_tick_size::node(),
            jnx::itch::price_tick_size_table_id::node(),
            jnx::itch::quantity::node(),
            jnx::itch::round_lot_size::node(),
            jnx::itch::short_selling_state::node(),
            jnx::itch::system_event::node(),
            jnx::itch::timestamp_nanoseconds::node(),
            jnx::itch::timestamp_seconds::node(),
            jnx::itch::trading_state::node(),
            jnx::itch::upper_price_limit::node()
        };
    }

    // parquet schema
    static auto schema() {
        return std::static_pointer_cast<parquet::schema::GroupNode>(parquet::schema::GroupNode::Make("schema", parquet::Repetition::REQUIRED, nodes()));
    }
};

inline auto& operator<<(parquet::StreamWriter& stream, const record& row) {
    return stream
        << row.pcap_index
        << row.pcap_timestamp
        << row.session
        << row.message_sequence
        << row.message_index
        << row.message_type
        << row.attribution
        << row.buy_sell_indicator
        << row.executed_quantity
        << row.group
        << row.lower_price_limit
        << row.match_number
        << row.new_order_number
        << row.order_number
        << row.order_type
        << row.orderbook_code
        << row.orderbook_id
        << row.original_order_number
        << row.price
        << row.price_decimals
        << row.price_start
        << row.price_tick_size
        << row.price_tick_size_table_id
        << row.quantity
        << row.round_lot_size
        << row.short_selling_state
        << row.system_event
        << row.timestamp_nanoseconds
        << row.timestamp_seconds
        << row.trading_state
        << row.upper_price_limit
        << parquet::EndRow;
}

inline auto& operator>>(parquet::StreamReader& stream, record& row) {
    return stream
        >> row.pcap_index
        >> row.pcap_timestamp
        >> row.session
        >> row.message_sequence
        >> row.message_index
        >> row.message_type
        >> row.attribution
        >> row.buy_sell_indicator
        >> row.executed_quantity
        >> row.group
        >> row.lower_price_limit
        >> row.match_number
        >> row.new_order_number
        >> row.order_number
        >> row.order_type
        >> row.orderbook_code
        >> row.orderbook_id
        >> row.original_order_number
        >> row.price
        >> row.price_decimals
        >> row.price_start
        >> row.price_tick_size
        >> row.price_tick_size_table_id
        >> row.quantity
        >> row.round_lot_size
        >> row.short_selling_state
        >> row.system_event
        >> row.timestamp_nanoseconds
        >> row.timestamp_seconds
        >> row.trading_state
        >> row.upper_price_limit
        >> parquet::EndRow;
}

inline auto& operator<<(std::ostream& stream, const record& row) {
    return stream
        << row.pcap_index <<","
        << row.pcap_timestamp <<","
        << row.session <<","
        << row.message_sequence <<","
        << row.message_index <<","
        << row.message_type <<","
        << row.attribution <<","
        << row.buy_sell_indicator <<","
        << row.executed_quantity <<","
        << row.group <<","
        << row.lower_price_limit <<","
        << row.match_number <<","
        << row.new_order_number <<","
        << row.order_number <<","
        << row.order_type <<","
        << row.orderbook_code <<","
        << row.orderbook_id <<","
        << row.original_order_number <<","
        << row.price <<","
        << row.price_decimals <<","
        << row.price_start <<","
        << row.price_tick_size <<","
        << row.price_tick_size_table_id <<","
        << row.quantity <<","
        << row.round_lot_size <<","
        << row.short_selling_state <<","
        << row.system_event <<","
        << row.timestamp_nanoseconds <<","
        << row.timestamp_seconds <<","
        << row.trading_state <<","
        << row.upper_price_limit <<","
        << std::endl;
}
}

///////////////////////////////////////////////////////////////////////
// itch converter
///////////////////////////////////////////////////////////////////////

// parquet options
struct options {
    std::string pcap_file = "itch.pcap";
    std::string parquet_file = "itch.parquet";
    std::int64_t max_row_group_size = 1000;
};

// itch converter
struct converter {

    jnx::itch::record record;
    parquet::StreamWriter writer;
    std::shared_ptr<arrow::io::FileOutputStream> outfile;
    std::shared_ptr<parquet::schema::GroupNode> schema;
    parquet::WriterProperties::Builder builder;

    explicit converter(const options& options) : record{} {
        PARQUET_ASSIGN_OR_THROW(outfile, arrow::io::FileOutputStream::Open(options.parquet_file));
        schema = jnx::itch::record::schema();
        writer = parquet::StreamWriter{parquet::ParquetFileWriter::Open(outfile, schema, builder.build())};
        writer.SetMaxRowGroupSize(options.max_row_group_size);
    }

    // return udp payload and length by skipping headers in a packet
    bool try_get_jnx_itch(const u_char *packet, u_char **payload, std::int32_t *length) {

        record.pcap_index.increment();

        *payload = const_cast<u_char*>(packet);

        // ethernet header
        *payload += 12;

        while (ntohs(*reinterpret_cast<const u_short*>(*payload)) != ETHERTYPE_IP) {
            *payload += 4;
        }
        *payload += 2;

        // internet protocol header
        auto ipheader = reinterpret_cast<const ip*>(*payload);
        u_int ip_length = ipheader->ip_hl * 4;
        *payload += ip_length;

        // found upd
        if (ipheader->ip_p == IPPROTO_UDP) {
            auto udp = reinterpret_cast<const udphdr*>(*payload);
            auto udphdr_length = sizeof(udphdr);
            *length = ntohs(udp->uh_ulen) - udphdr_length;
            *payload += udphdr_length;

            return true;
        }

        *length = 0;
        *payload = nullptr;

        return false;
    }

    // process itch packet
    void process(const pcap_pkthdr* header, const u_char* packet) {

        std::int32_t length = 0;
        u_char* current = nullptr;
        u_char* message = nullptr;

        if (try_get_jnx_itch(packet, &current, &length)) {

            record.pcap_timestamp.set(header);

            record.session.set(&current);
            record.message_sequence.set(&current);
            record.message_index.set(&current);

            while (record.message_index.increment()) {

                record.reset();

                record.message_length.set(&current, &message);
                record.message_type.set(&message);
                record.message_sequence.increment();

                process(&message, record.message_type.data);

                writer << record;
            }
        }
    }

    void process(u_char **message, const char message_type) {
        switch (message_type) {
            case 'T':
                process_timestamp_seconds_message(message);
                break;

            case 'S':
                process_system_event_message(message);
                break;

            case 'L':
                process_price_tick_size_message(message);
                break;

            case 'R':
                process_orderbook_directory_message(message);
                break;

            case 'H':
                process_trading_state_message(message);
                break;

            case 'Y':
                process_short_selling_price_restriction_state_message(message);
                break;

            case 'A':
                process_order_added_without_attributes_message(message);
                break;

            case 'F':
                process_order_added_with_attributes_message(message);
                break;

            case 'E':
                process_order_executed_message(message);
                break;

            case 'D':
                process_order_deleted_message(message);
                break;

            case 'U':
                process_order_replaced_message(message);
                break;

            default:
                break;
        }
    }

    void process_order_added_with_attributes_message(u_char **message) {
        record.timestamp_nanoseconds.set(message);
        record.order_number.set(message);
        record.buy_sell_indicator.set(message);
        record.quantity.set(message);
        record.orderbook_id.set(message);
        record.group.set(message);
        record.price.set(message);
        record.attribution.set(message);
        record.order_type.set(message);
    }

    void process_order_added_without_attributes_message(u_char **message) {
        record.timestamp_nanoseconds.set(message);
        record.order_number.set(message);
        record.buy_sell_indicator.set(message);
        record.quantity.set(message);
        record.orderbook_id.set(message);
        record.group.set(message);
        record.price.set(message);
    }

    void process_order_deleted_message(u_char **message) {
        record.timestamp_nanoseconds.set(message);
        record.order_number.set(message);
    }

    void process_order_executed_message(u_char **message) {
        record.timestamp_nanoseconds.set(message);
        record.order_number.set(message);
        record.executed_quantity.set(message);
        record.match_number.set(message);
    }

    void process_order_replaced_message(u_char **message) {
        record.timestamp_nanoseconds.set(message);
        record.original_order_number.set(message);
        record.new_order_number.set(message);
        record.quantity.set(message);
        record.price.set(message);
    }

    void process_orderbook_directory_message(u_char **message) {
        record.timestamp_nanoseconds.set(message);
        record.orderbook_id.set(message);
        record.orderbook_code.set(message);
        record.group.set(message);
        record.round_lot_size.set(message);
        record.price_tick_size_table_id.set(message);
        record.price_decimals.set(message);
        record.upper_price_limit.set(message);
        record.lower_price_limit.set(message);
    }

    void process_price_tick_size_message(u_char **message) {
        record.timestamp_nanoseconds.set(message);
        record.price_tick_size_table_id.set(message);
        record.price_tick_size.set(message);
        record.price_start.set(message);
    }

    void process_short_selling_price_restriction_state_message(u_char **message) {
        record.timestamp_nanoseconds.set(message);
        record.orderbook_id.set(message);
        record.group.set(message);
        record.short_selling_state.set(message);
    }

    void process_system_event_message(u_char **message) {
        record.timestamp_nanoseconds.set(message);
        record.group.set(message);
        record.system_event.set(message);
    }

    void process_timestamp_seconds_message(u_char **message) {
        record.timestamp_seconds.set(message);
    }

    void process_trading_state_message(u_char **message) {
        record.timestamp_nanoseconds.set(message);
        record.orderbook_id.set(message);
        record.group.set(message);
        record.trading_state.set(message);
    }

    // required to finish parquet file
    void close() {
        writer << parquet::EndRowGroup;
    }
};

void write_parquet(const options& options) {
    // open capture file
    char buffer[PCAP_ERRBUF_SIZE];
    const auto pcap = pcap_open_offline(options.pcap_file.c_str(), buffer);
    if (pcap == nullptr)
    {
        throw std::runtime_error("Unable to open file "); // need to add buffer
    }

    converter converter(options);

    // loop through packets
    pcap_pkthdr* header;
    const u_char* packet;

    while (true) {
        switch (pcap_next_ex(pcap, &header, &packet)) {
        case 1:
            converter.process(header, packet);
            break;
        case 0:
            // timeout
        case -1:
            //     std::cerr << "Error: " << pcap_geterr(p) << std::endl;
        case -2:
            // end-of-file
        default:
            converter.close();
            pcap_close(pcap);
            return;
        }
    }
}

void read_parquet(const std::string& parquet_file) {
    std::shared_ptr<arrow::io::ReadableFile> infile;

    PARQUET_ASSIGN_OR_THROW(infile, arrow::io::ReadableFile::Open(parquet_file));

    parquet::StreamReader reader{ parquet::ParquetFileReader::Open(infile) };

    jnx::itch::record record{};

    while (!reader.eof()) {
        reader >> record;
        std::cout << record;
    }
}

int main(const int argc, char** argv) {

    // parse arguments
    options options;

    if (argc == 3)
    {
        options.pcap_file = argv[1];
        options.parquet_file = argv[2];
    }
    else if (argc == 2)
    {
        options.pcap_file = argv[1];
    }
    else
    {
        std::cout << "usage: " << argv[0] << " pcap_file parquet_file" << std::endl;
        return -1;
    }

    write_parquet(options);

    read_parquet(options.parquet_file);

    return 0;
}
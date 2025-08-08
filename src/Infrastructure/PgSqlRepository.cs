using Npgsql;
using System.Data;

// Best results with scoped DI
public class PgSqlRepository : IDisposable, IPgSqlRepository
{
    private NpgsqlConnection _connection;

    public PgSqlRepository(string connectionString)
    {
        _connection = new NpgsqlConnection(connectionString);
    }

    private async Task EnsureConnectionOpenAsync()
    {
        if (_connection.State != ConnectionState.Open)
        {
            await _connection.OpenAsync();
        }
    }

    public async Task<int> ExecuteNonQueryAsync(string sql, params NpgsqlParameter[] parameters)
    {
        await EnsureConnectionOpenAsync();

        using (var command = new NpgsqlCommand(sql, _connection))
        {
            if (parameters != null && parameters.Length > 0)
            {
                command.Parameters.AddRange(parameters);
            }

            return await command.ExecuteNonQueryAsync();
        }
    }

    public async Task<object?> ExecuteScalarAsync(string sql, params NpgsqlParameter[] parameters)
    {
        await EnsureConnectionOpenAsync();

        using (var command = new NpgsqlCommand(sql, _connection))
        {
            if (parameters != null && parameters.Length > 0)
            {
                command.Parameters.AddRange(parameters);
            }

            return await command.ExecuteScalarAsync();
        }
    }

    public async Task<NpgsqlDataReader> ExecuteReaderAsync(string sql, params NpgsqlParameter[] parameters)
    {
        await EnsureConnectionOpenAsync();

        var command = new NpgsqlCommand(sql, _connection);
        if (parameters != null && parameters.Length > 0)
        {
            command.Parameters.AddRange(parameters);
        }

        return await command.ExecuteReaderAsync();
    }

    public async Task<NpgsqlTransaction> BeginTransactionAsync()
    {
        await EnsureConnectionOpenAsync();
        return await _connection.BeginTransactionAsync();
    }

    public async Task<int> ExecuteStoredProcedureAsync(string procedureName, params NpgsqlParameter[] parameters)
    {
        await EnsureConnectionOpenAsync();

        using (var command = new NpgsqlCommand(procedureName, _connection))
        {
            command.CommandType = CommandType.StoredProcedure;

            if (parameters != null && parameters.Length > 0)
            {
                command.Parameters.AddRange(parameters);
            }

            return await command.ExecuteNonQueryAsync();
        }
    }

    public async Task BulkInsertAsync(string tableName, DataTable dataTable)
    {
        await EnsureConnectionOpenAsync();

        using (var writer = await _connection.BeginBinaryImportAsync($"COPY {tableName} FROM STDIN (FORMAT BINARY)"))
        {
            foreach (DataRow row in dataTable.Rows)
            {
                object?[] values = row.ItemArray;
                await writer.WriteRowAsync(values: values);
            }

            await writer.CompleteAsync();
        }
    }

    public async Task<bool> TableExistsAsync(string tableName)
    {
        var sql = "SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = @tableName)";
        var parameter = new NpgsqlParameter("tableName", tableName);

        var result = await ExecuteScalarAsync(sql, parameter);

        // Обработка возможных null и DBNull
        return result switch
        {
            bool exists => exists,
            DBNull => false,
            null => false,
            _ => throw new InvalidCastException($"Unexpected result type: {result.GetType()}")
        };
    }

    public void Dispose()
    {
        if (_connection != null)
        {
            if (_connection.State != ConnectionState.Closed)
            {
                _connection.Close();
            }
            _connection.Dispose();
        }
    }
}
